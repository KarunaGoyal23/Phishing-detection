import pandas as pd
import numpy as np
import streamlit as st
from urllib.parse import urlparse
import re
from xgboost import XGBClassifier
import joblib
import os
from fusion_inference import load_default_model
from phishing_analyzer import URLAnalyzer

@st.cache_data
def load_data():
    try:
        df = pd.read_csv('phishing_dataset.csv')
        df.columns = df.columns.str.strip().str.lower()
        df['label'] = df['label'].astype(str).str.strip().str.lower()
        df['label'] = df['label'].fillna('legitimate')
        df['label'] = df['label'].map({'bad': 1, 'good': 0, 'legitimate': 0})
        df = df.dropna(subset=['label'])
        return df
    except FileNotFoundError:
        st.error("❌ File 'phishing_dataset.csv' not found.")
        return pd.DataFrame()

def extract_features(url):
    parsed = urlparse(url)
    return {
        'url_length': len(url),
        'has_https': int(parsed.scheme == 'https'),
        'num_dots': url.count('.'),
        'has_at': int('@' in url),
        'has_dash': int('-' in parsed.netloc),
        'has_ip': int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url))),
    }
@st.cache_resource
def load_model(df):
    model_path = "phishing_model.pkl"

    features_df = df['url'].apply(extract_features).apply(pd.Series)
    features_df['label'] = df['label']
    X = features_df.drop('label', axis=1)
    y = features_df['label']

    if os.path.exists(model_path):
        model = joblib.load(model_path)
    else:
        model = XGBClassifier(eval_metric='logloss', verbosity=1)
        model.fit(X, y)
        joblib.dump(model, model_path)
    return model

@st.cache_resource
def get_analyzer():
    return URLAnalyzer()

@st.cache_resource
def get_fusion_model():
    try:
        return load_default_model('advanced_fusion_artifact.pkl')
    except Exception:
        return None

def get_score_color(score):
    if score >= 80:
        return "#ff1e1e" 
    elif score >= 60:
        return "#ff7f0e"
    elif score >= 40:
        return "#ffcc0e"
    elif score >= 20:
        return "#1f77b4" 
    else:
        return "#2ca02c"  

st.set_page_config(page_title="Phishing URL Detector", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    .main-header {
        text-align: center;
        color: #1f77b4;
        margin-bottom: 30px;
    }
    .risk-score-container {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 15px;
        text-align: center;
        color: white;
        margin: 20px 0;
    }
    .safe-container {
        background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
        padding: 15px;
        border-radius: 10px;
        color: white;
        margin: 15px 0;
    }
    .warning-container {
        background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        padding: 15px;
        border-radius: 10px;
        color: white;
        margin: 15px 0;
    }
    .info-container {
        background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
        padding: 15px;
        border-radius: 10px;
        color: white;
        margin: 15px 0;
    }
    .stButton > button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 10px 30px;
        font-size: 16px;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<h1 class="main-header">🛡️ Advanced Phishing URL Detector</h1>', unsafe_allow_html=True)
st.markdown("""
<div style="text-align: center; margin-bottom: 30px;">
    <p style="font-size: 18px; color: #666;">
        🔍 Protect yourself from phishing attacks! Enter any URL below to check if it's safe or potentially malicious.
        <br>Our AI-powered system analyzes multiple factors to determine the risk level.
    </p>
</div>
""", unsafe_allow_html=True)

with st.expander("📝 Try These Example URLs", expanded=False):
    st.markdown("""
    **Safe URLs (should show low risk):**
    - https://www.google.com
    - https://www.github.com
    - https://www.microsoft.com
    
    **Suspicious patterns to test:**
    - http://g00gle.com (typosquatting)
    - https://payp4l-security.tk (suspicious TLD + typo)
    - http://192.168.1.1/login (IP address)
    - https://amazon-security.verification.tk (multiple suspicious elements)
    """)

col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    url_input = st.text_input("🔗 Enter a URL to analyze:", "", placeholder="Example: https://example.com")


tab1, tab2, tab3 = st.tabs(["📊 Risk Analysis", "🔍 Technical Details", "📚 Learn More"])

col1, col2, col3 = st.columns([1, 1, 1])
with col2:
    analyze_button = st.button("🔍 Analyze URL", use_container_width=True)

if not analyze_button:
    st.info("""
    ℹ️ **How to use this tool:**
    1. Enter a URL in the text box above
    2. Click the "Analyze URL" button
    3. Wait for the analysis to complete (may take a few seconds on first run)
    4. Review the results in the three tabs below
    
    **Note:** The first analysis may take longer as we load the AI models and dataset.
    """)

if analyze_button:
    if not url_input.strip():
        st.warning("⚠️ Please enter a URL to analyze.")
    else:
        with st.spinner("🔍 Initializing analysis components..."):
            try:
                with st.status("Loading components...") as status:
                    status.write("📊 Loading dataset...")
                    df = load_data()
                    if df.empty:
                        st.error("❌ Failed to load dataset. Please check if phishing_dataset.csv exists.")
                        st.stop()
                    
                    status.write("🔍 Initializing URL analyzer...")
                    analyzer = get_analyzer()
                    
                    status.write("🤖 Loading AI fusion model...")
                    fusion_model = get_fusion_model()
                    
                    status.write("✅ All components loaded successfully!")
                    status.update(label="✅ Analysis ready!", state="complete")
            except Exception as e:
                st.error(f"❌ Failed to initialize components: {str(e)}")
                st.info("💡 Try refreshing the page or check if all required files are present.")
                st.stop()
        
        with st.spinner("🔍 Analyzing URL... Please wait..."):
            try:
                analysis_results = analyzer.analyze_url(url_input)
                risk_score = analysis_results['risk_score']
                risk_level = analysis_results['risk_level']
                reasons = analysis_results['reasons']
                safe_url = analysis_results['safe_url']
                recommendation = analysis_results['recommendation']

                ai_prediction = None
                ai_prob = None
                if fusion_model is not None and getattr(fusion_model, 'is_trained', False):
                    try:
                        ai_res = fusion_model.predict(url_input)
                        ai_prediction = 'Phishing' if ai_res['prediction'] == 1 else 'Legitimate'
                        ai_prob = float(ai_res['probability'])
                    except Exception:
                        ai_prediction = None
                        ai_prob = None

                with tab1:
                    if risk_score >= 75:
                        score_color = "#ff1e1e"
                        icon = "🚨"
                        bg_class = "warning-container"
                    elif risk_score >= 50:
                        score_color = "#ff7f0e"
                        icon = "⚠️"
                        bg_class = "warning-container"
                    elif risk_score >= 30:
                        score_color = "#ffcc0e"
                        icon = "⚠️"
                        bg_class = "info-container"
                    elif risk_score >= 15:
                        score_color = "#1f77b4"
                        icon = "🔍"
                        bg_class = "info-container"
                    else:
                        score_color = "#2ca02c"
                        icon = "✅"
                        bg_class = "safe-container"

                    st.markdown(f"""
                    <div class="risk-score-container">
                        <h2>{icon} Risk Assessment</h2>
                        <div style="font-size:4em; font-weight:bold; margin: 20px 0;">
                            {risk_score}/100
                        </div>
                        <div style="font-size:1.5em; font-weight:bold;">
                            {risk_level}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)

                    if ai_prediction is not None and ai_prob is not None:
                        st.markdown("### 🤖 AI Model")
                        st.write(f"Prediction: {ai_prediction}")
                        st.write(f"Confidence: {ai_prob:.2%}")

                st.markdown(f"""
                <div class="{bg_class}">
                    <h3>🎯 Recommendation</h3>
                    <p style="font-size: 18px; margin: 0;"><strong>{recommendation}</strong></p>
                </div>
                """, unsafe_allow_html=True)
                
                if reasons:
                    st.markdown("### 🔍 Analysis Details")
                    for i, reason in enumerate(reasons, 1):
                        st.markdown(f"**{i}.** {reason}")

                if safe_url:
                    is_typosquatting = analysis_results['features'].get('is_typosquatting', 0) == 1
                    
                    if is_typosquatting or risk_score >= 30:
                        st.markdown(f"""
                        <div class="warning-container">
                            <h3>⚠️ Potential Typosquatting Detected</h3>
                            <p><strong>You entered:</strong> <code>{url_input}</code></p>
                            <p><strong>Did you mean to visit:</strong> <a href="{safe_url}" target="_blank" style="color: #fff; text-decoration: underline;">{safe_url}</a></p>
                            <p><em>Always verify URLs before entering sensitive information!</em></p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="info-container">
                            <h3>💡 Safe Alternative</h3>
                            <p>If you're looking for the official website, visit: <a href="{safe_url}" target="_blank" style="color: #fff; text-decoration: underline;"><strong>{safe_url}</strong></a></p>
                        </div>
                        """, unsafe_allow_html=True)

                if analysis_results['features'].get('known_phishing', False):
                    st.markdown("""
                    <div class="warning-container">
                        <h2>⛔ CONFIRMED PHISHING WEBSITE</h2>
                        <p style="font-size: 18px;">This URL is in our database of <strong>known phishing websites</strong>. Do not proceed!</p>
                        <p>🚨 <strong>NEVER</strong> enter your passwords, credit card details, or personal information on this site.</p>
                    </div>
                    """, unsafe_allow_html=True)

                with tab2:
                    st.markdown("### 🔍 URL Features Analysis")
                    features = analysis_results['features']

                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.markdown("#### 🌐 Domain Information")
                        st.markdown(f"**Domain:** `{features.get('domain', 'N/A')}`")
                        st.markdown(f"**TLD:** `{features.get('tld', 'N/A')}`")
                        st.markdown(f"**Subdomain:** `{features.get('subdomain', 'N/A') or 'None'}`")
                        st.markdown(f"**Full hostname:** `{features.get('hostname', 'N/A')}`")
                        if 'domain_age' in features and features['domain_age'] != -1:
                            st.markdown(f"**Domain age:** {features['domain_age']} days")
                        else:
                            st.markdown("**Domain age:** Unknown")
                        
                    with col2:
                        st.markdown("#### 📏 URL Characteristics")
                        st.markdown(f"**URL Length:** {features.get('url_length', 'N/A')} characters")
                        st.markdown(f"**HTTPS:** {'✅ Yes' if features.get('has_https', 0) == 1 else '❌ No'}")
                        st.markdown(f"**Path:** `{features.get('path', 'N/A') or '/'}`")
                        st.markdown(f"**Query string:** `{features.get('query_string', 'N/A') or 'None'}`")
                        st.markdown(f"**Scheme:** `{features.get('scheme', 'N/A')}`")
                        
                    with col3:
                        st.markdown("#### 🔒 Security Indicators")
                        st.markdown(f"**Contains IP:** {'❌ Yes' if features.get('has_ip', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Contains @ symbol:** {'❌ Yes' if features.get('has_at', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Contains dash:** {'⚠️ Yes' if features.get('has_dash', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Uses URL shortener:** {'❌ Yes' if features.get('uses_shortening_service', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Valid SSL:** {'✅ Yes' if features.get('has_valid_ssl', 1) == 1 else '❌ No'}")
                    
                    with col4:
                        st.markdown("#### 🎯 Brand Analysis")
                        st.markdown(f"**Typosquatting:** {'❌ Yes' if features.get('is_typosquatting', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Suspicious TLD:** {'❌ Yes' if features.get('has_suspicious_tld', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Abnormal subdomain:** {'❌ Yes' if features.get('abnormal_subdomain', 0) == 1 else '✅ No'}")
                        st.markdown(f"**Number of subdomains:** {features.get('num_subdomains', 0)}")
                        st.markdown(f"**Known phishing:** {'🚨 Yes' if features.get('known_phishing', False) else '✅ No'}")

                    if features.get('detected_brands'):
                        st.markdown("#### 🏷️ Brand Detection")
                        brand_list = ", ".join(features['detected_brands'])
                        st.info(f"🔍 **Detected references to:** {brand_list}")

                    st.markdown("#### 📊 Detailed Statistics")
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Number of dots", features.get('num_dots', 0))
                        st.metric("Number of digits", features.get('num_digits', 0))
                    
                    with col2:
                        st.metric("Domain length", features.get('domain_length', 0))
                        st.metric("Path length", features.get('path_length', 0))
                    
                    with col3:
                        st.metric("Query length", features.get('query_length', 0))
                        st.metric("Special characters", features.get('num_special_chars', 0))

                    if features.get('known_phishing'):
                        st.markdown("""
                        <div class="warning-container">
                            <h4>⚠️ URL Found in Phishing Database</h4>
                            <p>This URL has been previously identified as a phishing attempt in our database.</p>
                        </div>
                        """, unsafe_allow_html=True)

                with tab3:
                    st.markdown("### 📚 Understanding Phishing Protection")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown("""
                        #### 🎯 What is Phishing?
                        Phishing is a cybercrime where attackers impersonate legitimate organizations to steal sensitive information like:
                        - 🔑 Passwords and usernames
                        - 💳 Credit card numbers
                        - 🏦 Banking details
                        - 📧 Email access
                        - 📱 Social media accounts
                        
                        #### 🚨 Common Warning Signs
                        - **Urgent language** ("Act now or lose access!")
                        - **Suspicious URLs** (typos, extra characters)
                        - **Requests for sensitive info** via email/text
                        - **Poor grammar** or spelling mistakes
                        - **Generic greetings** ("Dear Customer")
                        """)
                    
                    with col2:
                        st.markdown("""
                        #### 🛡️ How to Stay Protected
                        
                        **🔍 Always Check URLs:**
                        - Look for HTTPS (lock icon)
                        - Verify the exact domain spelling
                        - Be wary of unusual TLDs (.tk, .ml, etc.)
                        
                        **📧 Email Safety:**
                        - Never click suspicious links
                        - Type URLs directly in browser
                        - Verify sender identity
                        
                        **🔐 Best Practices:**
                        - Use two-factor authentication
                        - Keep software updated
                        - Use reputable antivirus software
                        - Trust your instincts!
                        """)
                    
                    st.markdown("""
                    #### 🔍 How This Tool Works
                    
                    Our AI-powered phishing detector analyzes multiple factors:
                    
                    **Technical Analysis:**
                    - URL structure and length
                    - Domain age and registration
                    - SSL certificate validity
                    - IP address usage
                    
                    **Brand Protection:**
                    - Typosquatting detection
                    - Brand impersonation analysis
                    - Comparison with known legitimate sites
                    
                    **Database Matching:**
                    - Known phishing URL database
                    - Suspicious TLD patterns
                    - URL shortener detection
                    
                    **Risk Scoring:**
                    - Combines all factors into a 0-100 risk score
                    - Provides clear recommendations
                    - Suggests safe alternatives when applicable
                    """)
                    
            except Exception as e:
                st.error(f"❌ Error while analyzing URL: {str(e)}")
                st.markdown("""
                ### 🔧 Troubleshooting
                This error might occur due to:
                - Network connectivity issues
                - Invalid URL format
                - Server timeout
                
                **Please try:**
                1. Check your internet connection
                2. Verify the URL format (include http:// or https://)
                3. Try again in a few moments
            """)

st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; margin-top: 50px;">
    <p><strong>🛡️ Stay Safe Online!</strong></p>
    <p>This tool is designed to help identify potential phishing websites. Always exercise caution when sharing sensitive information online.</p>
    <p><em>⚠️ Disclaimer: This tool provides guidance but should not be the only security measure. Always verify suspicious URLs through official channels.</em></p>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div style="text-align: center; margin-top: 30px; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 10px; color: white;">
    <p style="margin: 0; font-size: 16px;">
        Made with ❤️ by <strong>Digar</strong> and <strong>Sanjay</strong>
    </p>
    <p style="margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">
        🚀 Protecting the web, one URL at a time
    </p>
</div>
""", unsafe_allow_html=True)

