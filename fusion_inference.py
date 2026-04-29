from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from urllib.parse import urlparse

try:
    import joblib
except Exception as e:  
    joblib = None  


def _extract_url_numeric_features(url: str) -> Dict[str, Any]:
    if not isinstance(url, str):
        url = ''
    try:
        parsed = urlparse(url if re.match(r'^https?://', url) else 'http://' + url)
        domain = parsed.netloc or ''
        path = parsed.path or ''
        query = parsed.query or ''
        s = url
        feats: Dict[str, Any] = {}

        feats['url_len'] = len(s)
        feats['num_digits'] = sum(ch.isdigit() for ch in s)
        feats['num_letters'] = sum(ch.isalpha() for ch in s)
        feats['num_special'] = sum((not ch.isalnum()) and (not ch.isspace()) for ch in s)

        for ch, name in [('.', 'dots'),('-', 'hyphens'),('_','underscores'),('/', 'slashes'),('?', 'qmarks'),('=','equals'),('&','amps'),('%','perc'),('#','hash')]:
            feats[f'cnt_{name}'] = s.count(ch)

        feats['domain_len'] = len(domain)
        feats['path_len'] = len(path)
        feats['path_depth'] = path.count('/')
        feats['query_len'] = len(query)
        feats['num_params'] = (query.count('&') + 1) if query else 0
        feats['has_https'] = 1 if parsed.scheme == 'https' else 0
        feats['has_www'] = 1 if domain.startswith('www.') else 0

        feats['domain_is_ip'] = 1 if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', domain) else 0
        feats['suspicious_tld'] = 1 if re.search(r'\.(tk|ml|ga|cf|gq|xyz|top|ru|click|link|bid|party|win)(?:/|$)', domain.lower()) else 0
        feats['brand_terms'] = 1 if re.search(r'(paypal|google|facebook|apple|microsoft|yahoo|amazon)', s.lower()) else 0
        feats['num_subdomains'] = max(0, domain.count('.') - 1) if domain else 0
        return feats
    except Exception:
        return {
            'url_len':0,'num_digits':0,'num_letters':0,'num_special':0,
            'cnt_dots':0,'cnt_hyphens':0,'cnt_underscores':0,'cnt_slashes':0,'cnt_qmarks':0,'cnt_equals':0,'cnt_amps':0,'cnt_perc':0,'cnt_hash':0,
            'domain_len':0,'path_len':0,'path_depth':0,'query_len':0,'num_params':0,'has_https':0,'has_www':0,'domain_is_ip':0,'suspicious_tld':0,'brand_terms':0,'num_subdomains':0,
        }


class FusionArtifactModel:
    """Thin wrapper around advanced_fusion_artifact.pkl for server/GUI use."""

    def __init__(self, artifact_path: str = 'advanced_fusion_artifact.pkl') -> None:
        if joblib is None:
            raise RuntimeError('joblib is required to load the fusion artifact')
        self.artifact_path = artifact_path
        self.artifact: Dict[str, Any] = joblib.load(artifact_path)

        self.models: Dict[str, Any] = self.artifact.get('models', {})
        self.meta = self.artifact.get('meta', None)
        self.names: List[str] = list(self.artifact.get('names', []))
        self.weights: np.ndarray = np.array(self.artifact.get('weights', []), dtype=float)
        self.scaler_num = self.artifact.get('scaler_num', None)
        self.use_transformer: bool = bool(self.artifact.get('use_transformer', False))
        self.fitted_vec = self.artifact.get('fitted_vec', None)

        # Try to initialize transformer if used in training
        self.st_model = None
        self.text_ready = False
        if self.use_transformer:
            try:
                from sentence_transformers import SentenceTransformer 
                self.st_model = SentenceTransformer('all-MiniLM-L6-v2')
                self.text_ready = True
            except Exception:
                # If we trained with transformer but can't load now, we cannot use the text model
                self.text_ready = False
        else:
            # TF-IDF path uses fitted_vec if present
            self.text_ready = self.fitted_vec is not None

        # Filter out text-based model if text isn't ready
        self.available_names: List[str] = []
        self._name_to_index: Dict[str, int] = {n: i for i, n in enumerate(self.names)}
        for n in self.names:
            if n == 'Transformer' and not self.text_ready:
                continue
            self.available_names.append(n)

        # Precompute renormalized weights for the available models
        if len(self.weights) == len(self.names) and len(self.available_names) > 0:
            mask = np.array([n in self.available_names for n in self.names], dtype=bool)
            w = self.weights[mask].astype(float)
            s = w.sum()
            self.weights_available = (w / s) if s > 0 else np.ones_like(w) / len(w)
        else:
            self.weights_available = np.ones(len(self.available_names), dtype=float) / max(1, len(self.available_names))

        self.is_trained = True

    def _build_numeric(self, url: str):
        Xn = pd.DataFrame([_extract_url_numeric_features(url)])
        Xn_scaled = self.scaler_num.transform(Xn) if self.scaler_num is not None else Xn.values
        return Xn, Xn_scaled

    def _build_text(self, url: str):
        if not self.text_ready:
            return None
        if self.use_transformer and self.st_model is not None:
            return self.st_model.encode([url], convert_to_numpy=True, show_progress_bar=False)
        if self.fitted_vec is not None:
            return self.fitted_vec.transform([url])
        return None

    def predict(self, url: str) -> Dict[str, Any]:
        """Return {'prediction': 0/1, 'probability': float} using weighted ensemble.

        Falls back gracefully if the text model isn't available at runtime.
        """
        Xn, Xn_scaled = self._build_numeric(url)
        Xt = self._build_text(url)

        probas: List[np.ndarray] = []
        names_used: List[str] = []

        for n in self.available_names:
            if n == 'XGBoost':
                probas.append(self.models[n].predict_proba(Xn)[:, 1].reshape(-1, 1))
                names_used.append(n)
            elif n == 'GradientBoosting':
                probas.append(self.models[n].predict_proba(Xn)[:, 1].reshape(-1, 1))
                names_used.append(n)
            elif n == 'LogisticRegression':
                probas.append(self.models[n].predict_proba(Xn_scaled)[:, 1].reshape(-1, 1))
                names_used.append(n)
            elif n == 'Transformer' and Xt is not None:
                probas.append(self.models[n].predict_proba(Xt)[:, 1].reshape(-1, 1))
                names_used.append(n)

        if not probas:
            return {'prediction': 0, 'probability': 0.0}

        P = np.hstack(probas)

        if names_used == self.available_names:
            w = self.weights_available
        else:
            idxs = [self._name_to_index[n] for n in names_used]
            w_sel = self.weights[idxs].astype(float)
            s = w_sel.sum()
            w = (w_sel / s) if s > 0 else np.ones_like(w_sel) / len(w_sel)

        avg_proba = float((P * w.reshape(1, -1)).sum(axis=1)[0])
        yhat = int(avg_proba >= 0.5)
        return {'prediction': yhat, 'probability': avg_proba}


def load_default_model(path: str = 'advanced_fusion_artifact.pkl') -> Optional[FusionArtifactModel]:
    try:
        return FusionArtifactModel(path)
    except Exception:
        return None
