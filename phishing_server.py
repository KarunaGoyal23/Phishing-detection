import socket
import json
import threading
import time
import logging
from datetime import datetime
import pickle
import os
from advanced_phishing_model import AdvancedPhishingDetector
from fusion_inference import load_default_model, FusionArtifactModel
from phishing_analyzer import URLAnalyzer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_server.log'),
        logging.StreamHandler()
    ]
)

class PhishingDetectionServer:
    def __init__(self, host='0.0.0.0', port=5000, max_connections=10):
        self.host = host
        self.port = port
        self.max_connections = max_connections
        self.server_socket = None
        self.clients = []
        self.running = False

        self.detector = None
        self.fusion_model = None
        self.analyzer = None
        self.load_models()

        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'start_time': datetime.now(),
            'active_connections': 0
        }
    
    def load_models(self):
        """Load the trained models"""
        try:
            if os.path.exists('advanced_fusion_artifact.pkl'):
                self.fusion_model = load_default_model('advanced_fusion_artifact.pkl')
                if self.fusion_model is not None and getattr(self.fusion_model, 'is_trained', False):
                    logging.info("Advanced fusion artifact loaded successfully")
                else:
                    self.fusion_model = None
                    logging.warning("Fusion artifact not usable")

            self.analyzer = URLAnalyzer()
            logging.info("Basic analyzer loaded successfully")

        except Exception as e:
            logging.error(f"Error loading models: {e}")
            self.detector = None
            self.analyzer = None
    
    def start_server(self):
        """Start the phishing detection server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            
            self.running = True
            logging.info(f"Phishing Detection Server started on {self.host}:{self.port}")
            logging.info(f"Maximum connections: {self.max_connections}")

            stats_thread = threading.Thread(target=self._print_stats, daemon=True)
            stats_thread.start()

            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    logging.info(f"New connection from {client_address}")

                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address),
                        daemon=True
                    )
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        logging.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.stop_server()
    
    def stop_server(self):
        """Stop the server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logging.info("Server stopped")
    
    def _handle_client(self, client_socket, client_address):
        """Handle individual client connections"""
        self.stats['active_connections'] += 1
        
        try:
            while self.running:
                data = client_socket.recv(4096)
                if not data:
                    break
                
                try:
                    request = json.loads(data.decode('utf-8'))
                    self.stats['total_requests'] += 1

                    response = self._process_request(request)

                    response_data = json.dumps(response, indent=2).encode('utf-8')
                    client_socket.send(response_data)
                    
                    self.stats['successful_requests'] += 1
                    
                except json.JSONDecodeError as e:
                    error_response = {
                        'status': 'error',
                        'message': f'Invalid JSON format: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }
                    client_socket.send(json.dumps(error_response).encode('utf-8'))
                    self.stats['failed_requests'] += 1
                    
                except Exception as e:
                    error_response = {
                        'status': 'error',
                        'message': f'Server error: {str(e)}',
                        'timestamp': datetime.now().isoformat()
                    }
                    client_socket.send(json.dumps(error_response).encode('utf-8'))
                    self.stats['failed_requests'] += 1
                    logging.error(f"Error processing request: {e}")
                    
        except Exception as e:
            logging.error(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            self.stats['active_connections'] -= 1
            logging.info(f"Connection closed for {client_address}")
    
    def _process_request(self, request):
        """Process client request and return response"""
        request_type = request.get('type', 'analyze')
        url = request.get('url', '')
        
        if not url:
            return {
                'status': 'error',
                'message': 'URL is required',
                'timestamp': datetime.now().isoformat()
            }
        
        try:
            if request_type == 'analyze':
                return self._analyze_url(url)
            elif request_type == 'batch_analyze':
                urls = request.get('urls', [])
                return self._batch_analyze_urls(urls)
            elif request_type == 'health':
                return self._health_check()
            elif request_type == 'stats':
                return self._get_stats()
            else:
                return {
                    'status': 'error',
                    'message': f'Unknown request type: {request_type}',
                    'timestamp': datetime.now().isoformat()
                }
                
        except Exception as e:
            logging.error(f"Error processing request: {e}")
            return {
                'status': 'error',
                'message': f'Processing error: {str(e)}',
                'timestamp': datetime.now().isoformat()
            }
    
    def _analyze_url(self, url):
        """Analyze a single URL using both models"""
        start_time = time.time()

        basic_analysis = self.analyzer.analyze_url(url)
        advanced_analysis = None
        try:
            if self.fusion_model is not None and getattr(self.fusion_model, 'is_trained', False):
                res = self.fusion_model.predict(url)
                advanced_analysis = {
                    'prediction': res['prediction'],
                    'probability': float(res['probability']),
                    'is_phishing': res['prediction'] == 1
                }
            elif self.detector and self.detector.is_trained:
                advanced_result = self.detector.predict(url)
                advanced_analysis = {
                    'prediction': advanced_result['prediction'],
                    'probability': float(advanced_result['probability']),
                    'is_phishing': advanced_result['prediction'] == 1
                }
        except Exception as e:
            logging.warning(f"Advanced model prediction failed: {e}")

        combined_risk_score = basic_analysis['risk_score']
        if advanced_analysis:
            advanced_score = advanced_analysis['probability'] * 100
            combined_risk_score = (basic_analysis['risk_score'] * 0.7) + (advanced_score * 0.3)
        
        processing_time = time.time() - start_time
        
        response = {
            'status': 'success',
            'url': url,
            'analysis': {
                'basic': {
                    'risk_score': basic_analysis['risk_score'],
                    'risk_level': basic_analysis['risk_level'],
                    'reasons': basic_analysis['reasons'],
                    'safe_url': basic_analysis['safe_url'],
                    'recommendation': basic_analysis['recommendation']
                },
                'advanced': advanced_analysis,
                'combined': {
                    'risk_score': round(combined_risk_score, 2),
                    'risk_level': self._get_risk_level(combined_risk_score),
                    'processing_time': round(processing_time, 3)
                }
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return response
    
    def _batch_analyze_urls(self, urls):
        """Analyze multiple URLs"""
        if not urls or len(urls) > 100: 
            return {
                'status': 'error',
                'message': 'Invalid batch size (1-100 URLs allowed)',
                'timestamp': datetime.now().isoformat()
            }
        
        results = []
        for url in urls:
            try:
                result = self._analyze_url(url)
                results.append(result)
            except Exception as e:
                results.append({
                    'status': 'error',
                    'url': url,
                    'message': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        return {
            'status': 'success',
            'batch_results': results,
            'total_urls': len(urls),
            'timestamp': datetime.now().isoformat()
        }

    def _health_check(self):
        """Health check endpoint"""
        return {
            'status': 'success',
            'health': {
                'server_running': self.running,
                'basic_analyzer_loaded': self.analyzer is not None,
                'advanced_model_loaded': (
                    (self.fusion_model is not None and getattr(self.fusion_model, 'is_trained', False)) or
                    (self.detector is not None and self.detector.is_trained)
                ),
                'active_connections': self.stats['active_connections'],
                'uptime_seconds': (datetime.now() - self.stats['start_time']).total_seconds()
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_stats(self):
        """Get server statistics"""
        uptime = datetime.now() - self.stats['start_time']
        return {
            'status': 'success',
            'statistics': {
                'total_requests': self.stats['total_requests'],
                'successful_requests': self.stats['successful_requests'],
                'failed_requests': self.stats['failed_requests'],
                'success_rate': round(self.stats['successful_requests'] / max(self.stats['total_requests'], 1) * 100, 2),
                'active_connections': self.stats['active_connections'],
                'uptime_seconds': uptime.total_seconds(),
                'start_time': self.stats['start_time'].isoformat()
            },
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_risk_level(self, score):
        """Convert risk score to risk level"""
        if score >= 75:
            return "Critical Risk"
        elif score >= 50:
            return "High Risk"
        elif score >= 30:
            return "Medium Risk"
        elif score >= 15:
            return "Low Risk"
        else:
            return "Minimal Risk"
    
    def _print_stats(self):
        """Print server statistics periodically"""
        while self.running:
            time.sleep(60)  # Print stats every minute
            if self.stats['total_requests'] > 0:
                success_rate = (self.stats['successful_requests'] / self.stats['total_requests']) * 100
                uptime = datetime.now() - self.stats['start_time']
                logging.info(f"Stats - Requests: {self.stats['total_requests']}, "
                           f"Success Rate: {success_rate:.1f}%, "
                           f"Active Connections: {self.stats['active_connections']}, "
                           f"Uptime: {uptime}")

def main():
    """Main function to run the server"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Phishing Detection Server')
    parser.add_argument('--host', default='0.0.0.0', help='Server host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5000, help='Server port (default: 5000)')
    parser.add_argument('--max-connections', type=int, default=10, help='Maximum connections (default: 10)')
    
    args = parser.parse_args()

    server = PhishingDetectionServer(
        host=args.host,
        port=args.port,
        max_connections=args.max_connections
    )
    
    try:
        server.start_server()
    except KeyboardInterrupt:
        logging.info("Server interrupted by user")
    except Exception as e:
        logging.error(f"Server error: {e}")

if __name__ == "__main__":
    main() 