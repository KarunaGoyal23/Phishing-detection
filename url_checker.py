import argparse
import sys
from phishing_analyzer import URLAnalyzer
from fusion_inference import load_default_model

def main():
    parser = argparse.ArgumentParser(description='Advanced Phishing URL Detector - Command Line Interface')
    parser.add_argument('url', help='URL to analyze for phishing risk')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed analysis')
    parser.add_argument('-j', '--json', action='store_true', help='Output results in JSON format')
    parser.add_argument('-s', '--safe-url', action='store_true', help='Only show safe URL suggestion if available')
    parser.add_argument('--ai', action='store_true', help='Also run AI fusion model prediction if available')
    
    args = parser.parse_args()
    
    try:
        analyzer = URLAnalyzer()
        fusion_model = load_default_model('advanced_fusion_artifact.pkl') if args.ai else None

        print(f"Analyzing URL: {args.url}")
        print("-" * 50)
        
        results = analyzer.analyze_url(args.url)
        ai_output = None
        if fusion_model is not None and getattr(fusion_model, 'is_trained', False):
            try:
                ai_res = fusion_model.predict(args.url)
                ai_output = {
                    'prediction': 'Phishing' if ai_res['prediction'] == 1 else 'Legitimate',
                    'probability': float(ai_res['probability'])
                }
            except Exception:
                ai_output = None
        
        if args.json:
            import json
            out = {'analysis': results}
            if ai_output is not None:
                out['ai'] = ai_output
            print(json.dumps(out, indent=2, default=str))
            return
        
        if args.safe_url:
            if results['safe_url']:
                print(f"Safe alternative: {results['safe_url']}")
            else:
                print("No safe alternative found.")
            return

        print(f"Risk Score: {results['risk_score']}/100")
        print(f"Risk Level: {results['risk_level']}")
        print(f"Recommendation: {results['recommendation']}")

        if ai_output is not None:
            print("\nAI Model:")
            print(f"Prediction: {ai_output['prediction']}")
            print(f"Confidence: {ai_output['probability']:.2%}")
        
        if results['safe_url']:
            print(f"Safe Alternative: {results['safe_url']}")
        
        if args.verbose:
            print("\nDetailed Analysis:")
            print("-" * 30)
            
            features = results['features']
            print(f"Domain: {features.get('domain', 'N/A')}")
            print(f"TLD: {features.get('tld', 'N/A')}")
            print(f"HTTPS: {'Yes' if features.get('has_https', 0) else 'No'}")
            print(f"Domain Age: {features.get('domain_age', 'Unknown')} days")
            print(f"Typosquatting: {'Yes' if features.get('is_typosquatting', 0) else 'No'}")
            print(f"Known Phishing: {'Yes' if features.get('known_phishing', False) else 'No'}")
            
            if features.get('detected_brands'):
                print(f"Detected Brands: {', '.join(features['detected_brands'])}")
        
        print(f"\nReasons for assessment:")
        for i, reason in enumerate(results['reasons'], 1):
            print(f"{i}. {reason}")
            
    except Exception as e:
        print(f"Error analyzing URL: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
