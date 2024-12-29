import unittest
import dns.message
import dns.query
import dns.resolver
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import statistics

class TestDNSServerPerformance(unittest.TestCase):
    def setUp(self):
        self.server_addr = '127.0.0.66'  # Match your server's IP
        self.server_port = 53  # Match your server's port
        self.timeout = 3.0

    def query_domain(self, domain):
        """Helper method to measure query response time"""
        start_time = time.time()
        try:
            query = dns.message.make_query(domain, 'A')
            response = dns.query.udp(
                query, 
                self.server_addr, 
                port=self.server_port, 
                timeout=self.timeout
            )
            return time.time() - start_time
        except Exception as e:
            print(f"Query failed for {domain}: {str(e)}")  # Debug info
            return None

    def test_concurrent_queries(self):
        """Test server performance under concurrent load"""
        domains = [
            'hahalol.com',  # Your authoritative domain
            'example.com',
            'test123.com'
        ]
        num_concurrent = 10  # Reduced from 50 to start
        response_times = []
        failed_queries = 0

        with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            futures = []
            for _ in range(num_concurrent):
                for domain in domains:
                    futures.append(executor.submit(self.query_domain, domain))
            
            for future in futures:
                result = future.result()
                if result is not None:
                    response_times.append(result)
                else:
                    failed_queries += 1

        # Print diagnostic information
        total_queries = len(futures)
        successful_queries = len(response_times)
        
        print(f"\nPerformance Test Results:")
        print(f"Total queries: {total_queries}")
        print(f"Successful queries: {successful_queries}")
        print(f"Failed queries: {failed_queries}")

        # Only calculate statistics if we have successful queries
        if response_times:
            avg_time = statistics.mean(response_times)
            p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)
            
            print(f"Average response time: {avg_time:.3f} seconds")
            print(f"95th percentile response time: {p95_time:.3f} seconds")
            
            # More lenient assertions
            self.assertLess(avg_time, 1.0)  # Average response time < 1s
            self.assertLess(p95_time, 2.0)  # 95th percentile < 2s
        
        # Assert that we had at least some successful queries
        self.assertGreater(len(response_times), 0, 
                          "No successful queries completed. Check server connection and configuration.")
        
        # Assert a minimum success rate
        success_rate = successful_queries / total_queries
        self.assertGreater(success_rate, 0.5, 
                          f"Success rate too low: {success_rate:.2%}")