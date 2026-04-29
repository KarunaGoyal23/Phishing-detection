import socket
import json
import time
import argparse
import sys
from datetime import datetime
import threading
import queue

class PhishingDetectionClient:
    def __init__(self, host='localhost', port=5000, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.connected = False
        
    def connect(self):
        """Connect to the phishing detection server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self.timeout)
            self.socket.connect((self.host, self.port))
            self.connected = True
            print(f"✅ Connected to server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"❌ Failed to connect to server: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.socket:
            self.socket.close()
        self.connected = False
        print("🔌 Disconnected from server")
    
    def send_request(self, request):
        """Send a request to the server and get response"""
        if not self.connected:
            if not self.connect():
                return None
        
        try:
            request_data = json.dumps(request).encode('utf-8')
            self.socket.send(request_data)

            response_data = self.socket.recv(8192)
            response = json.loads(response_data.decode('utf-8'))
            
            return response
            
        except Exception as e:
            print(f"❌ Error communicating with server: {e}")
            self.connected = False
            return None
    
    def analyze_url(self, url):
        """Analyze a single URL"""
        request = {
            'type': 'analyze',
            'url': url
        }
        
        print(f"🔍 Analyzing URL: {url}")
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            return self._display_analysis(response)
        else:
            error_msg = response.get('message', 'Unknown error') if response else 'No response from server'
            print(f"❌ Analysis failed: {error_msg}")
            return None
    
    def batch_analyze_urls(self, urls):
        """Analyze multiple URLs"""
        request = {
            'type': 'batch_analyze',
            'urls': urls
        }
        
        print(f"🔍 Analyzing {len(urls)} URLs...")
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            return self._display_batch_analysis(response)
        else:
            error_msg = response.get('message', 'Unknown error') if response else 'No response from server'
            print(f"❌ Batch analysis failed: {error_msg}")
            return None
    
    def health_check(self):
        """Check server health"""
        request = {
            'type': 'health'
        }
        
        print("🏥 Checking server health...")
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            return self._display_health(response)
        else:
            error_msg = response.get('message', 'Unknown error') if response else 'No response from server'
            print(f"❌ Health check failed: {error_msg}")
            return None
    
    def get_stats(self):
        """Get server statistics"""
        request = {
            'type': 'stats'
        }
        
        print("📊 Getting server statistics...")
        response = self.send_request(request)
        
        if response and response.get('status') == 'success':
            return self._display_stats(response)
        else:
            error_msg = response.get('message', 'Unknown error') if response else 'No response from server'
            print(f"❌ Stats request failed: {error_msg}")
            return None
    
    def _display_analysis(self, response):
        """Display analysis results"""
        analysis = response['analysis']
        url = response['url']
        
        print("\n" + "="*60)
        print(f"📊 ANALYSIS RESULTS FOR: {url}")
        print("="*60)

        combined = analysis['combined']
        risk_score = combined['risk_score']
        risk_level = combined['risk_level']
        processing_time = combined['processing_time']

        if risk_score >= 75:
            risk_icon = "🚨"
            risk_color = "RED"
        elif risk_score >= 50:
            risk_icon = "⚠️"
            risk_color = "ORANGE"
        elif risk_score >= 30:
            risk_icon = "🔍"
            risk_color = "YELLOW"
        elif risk_score >= 15:
            risk_icon = "🔵"
            risk_color = "BLUE"
        else:
            risk_icon = "✅"
            risk_color = "GREEN"
        
        print(f"\n{risk_icon} COMBINED RISK ASSESSMENT")
        print(f"Risk Score: {risk_score}/100 ({risk_color})")
        print(f"Risk Level: {risk_level}")
        print(f"Processing Time: {processing_time}s")

        basic = analysis['basic']
        print(f"Recommendation: {basic['recommendation']}")
        if basic['safe_url']:
            print(f"Safe Alternative: {basic['safe_url']}")
        
        if basic['reasons']:
            print(f"\n🔍 Risk Factors:")
            for i, reason in enumerate(basic['reasons'], 1):
                print(f"  {i}. {reason}")

        advanced = analysis.get('advanced')
        if advanced:
            print(f"\n🤖 ADVANCED AI ANALYSIS")
            print(f"Prediction: {'Phishing' if advanced['is_phishing'] else 'Legitimate'}")
            print(f"Confidence: {advanced['probability']:.2%}")
        
        print("\n" + "="*60)
        return response
    
    def _display_batch_analysis(self, response):
        """Display batch analysis results"""
        batch_results = response['batch_results']
        total_urls = response['total_urls']
        
        print(f"\n📊 BATCH ANALYSIS RESULTS ({total_urls} URLs)")
        print("="*60)
        
        phishing_count = 0
        legitimate_count = 0
        error_count = 0
        
        for i, result in enumerate(batch_results, 1):
            if result.get('status') == 'success':
                analysis = result['analysis']
                url = result['url']
                risk_score = analysis['combined']['risk_score']
                
                if risk_score >= 50:
                    phishing_count += 1
                    icon = "🚨"
                else:
                    legitimate_count += 1
                    icon = "✅"
                
                print(f"{i:2d}. {icon} {url:<40} Score: {risk_score:5.1f}")
            else:
                error_count += 1
                print(f"{i:2d}. ❌ {result.get('url', 'Unknown')} - {result.get('message', 'Error')}")
        
        print("\n" + "="*60)
        print(f"📈 SUMMARY:")
        print(f"Phishing URLs: {phishing_count}")
        print(f"Legitimate URLs: {legitimate_count}")
        print(f"Errors: {error_count}")
        print(f"Success Rate: {((total_urls - error_count) / total_urls * 100):.1f}%")
        print("="*60)
        
        return response
    
    def _display_health(self, response):
        """Display health check results"""
        health = response['health']
        
        print("\n🏥 SERVER HEALTH CHECK")
        print("="*40)
        print(f"Server Running: {'✅ Yes' if health['server_running'] else '❌ No'}")
        print(f"Basic Analyzer: {'✅ Loaded' if health['basic_analyzer_loaded'] else '❌ Not Loaded'}")
        print(f"Advanced Model: {'✅ Loaded' if health['advanced_model_loaded'] else '❌ Not Loaded'}")
        print(f"Active Connections: {health['active_connections']}")
        print(f"Uptime: {health['uptime_seconds']:.1f} seconds")
        print("="*40)
        
        return response
    
    def _display_stats(self, response):
        """Display server statistics"""
        stats = response['statistics']
        
        print("\n📊 SERVER STATISTICS")
        print("="*40)
        print(f"Total Requests: {stats['total_requests']}")
        print(f"Successful Requests: {stats['successful_requests']}")
        print(f"Failed Requests: {stats['failed_requests']}")
        print(f"Success Rate: {stats['success_rate']}%")
        print(f"Active Connections: {stats['active_connections']}")
        print(f"Uptime: {stats['uptime_seconds']:.1f} seconds")
        print(f"Start Time: {stats['start_time']}")
        print("="*40)
        
        return response
    
    def interactive_mode(self):
        """Run in interactive mode"""
        print("🔌 Interactive Mode - Type 'quit' to exit")
        print("Commands: analyze <url>, batch <url1,url2,...>, health, stats, quit")
        print("-" * 50)
        
        while True:
            try:
                command = input("\n> ").strip()
                
                if command.lower() == 'quit':
                    break
                elif command.lower() == 'health':
                    self.health_check()
                elif command.lower() == 'stats':
                    self.get_stats()
                elif command.startswith('analyze '):
                    url = command[8:].strip()
                    if url:
                        self.analyze_url(url)
                    else:
                        print("❌ Please provide a URL to analyze")
                elif command.startswith('batch '):
                    urls_str = command[6:].strip()
                    if urls_str:
                        urls = [url.strip() for url in urls_str.split(',')]
                        self.batch_analyze_urls(urls)
                    else:
                        print("❌ Please provide URLs to analyze (comma-separated)")
                else:
                    print("❌ Unknown command. Available commands:")
                    print("  analyze <url> - Analyze a single URL")
                    print("  batch <url1,url2,...> - Analyze multiple URLs")
                    print("  health - Check server health")
                    print("  stats - Get server statistics")
                    print("  quit - Exit interactive mode")
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
        
        self.disconnect()

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Phishing Detection Client')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=5000, help='Server port (default: 5000)')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout (default: 10s)')
    parser.add_argument('--url', help='Single URL to analyze')
    parser.add_argument('--batch', help='Comma-separated URLs to analyze')
    parser.add_argument('--health', action='store_true', help='Check server health')
    parser.add_argument('--stats', action='store_true', help='Get server statistics')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    
    args = parser.parse_args()

    client = PhishingDetectionClient(
        host=args.host,
        port=args.port,
        timeout=args.timeout
    )
    
    try:
        if not client.connect():
            sys.exit(1)

        if args.health:
            client.health_check()
        elif args.stats:
            client.get_stats()
        elif args.url:
            client.analyze_url(args.url)
        elif args.batch:
            urls = [url.strip() for url in args.batch.split(',')]
            client.batch_analyze_urls(urls)
        elif args.interactive:
            client.interactive_mode()
        else:
            client.interactive_mode()
            
    except KeyboardInterrupt:
        print("\n👋 Interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()