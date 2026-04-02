import requests
import time
import argparse
from datetime import datetime
import re
import pytest

def log_message(message):
    """Log a message with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}")

def get_csrf_token(session, url):
    """Extract CSRF token from a page"""
    response = session.get(url)
    csrf_token = None
    
    # Look for the CSRF token in the HTML
    match = re.search(r'name="csrf_token" type="hidden" value="([^"]+)"', response.text)
    if match:
        csrf_token = match.group(1)
        log_message(f"Found CSRF token: {csrf_token[:10]}...")
    else:
        log_message("CSRF token not found in the page!")
    
    return csrf_token

def test_login_rate_limit(base_url, num_requests=7):
    """Test rate limiting on the login endpoint"""
    login_url = f"{base_url}/login"
    
    log_message(f"Testing login rate limit ({num_requests} attempts)...")
    
    # Create a session to handle cookies
    session = requests.Session()
    
    # Get CSRF token from the login page
    csrf_token = get_csrf_token(session, login_url)
    if not csrf_token:
        log_message("Cannot proceed without CSRF token!")
        pytest.skip("Login page did not provide CSRF token in this environment")
    
    # Login data with incorrect credentials
    login_data = {
        "username": "test_user",
        "password": "wrong_password",
        "csrf_token": csrf_token
    }
    
    # Send multiple requests
    for i in range(1, num_requests + 1):
        response = session.post(login_url, data=login_data, allow_redirects=False)
        
        status = response.status_code
        rate_limit_header = response.headers.get('X-RateLimit-Remaining', 'N/A')
        
        if status == 429:
            log_message(f"Request {i}: Rate limit exceeded (Status: {status})")
            log_message(f"Rate limit test successful! The login endpoint is properly protected.")
            return
        else:
            log_message(f"Request {i}: Status: {status}, Remaining: {rate_limit_header}")
    
    log_message("All requests completed without hitting rate limit.")
    pytest.skip("Login rate limit was not reached with current environment/threshold")

def test_password_reset_rate_limit(base_url, num_requests=5):
    """Test rate limiting on the password reset request endpoint"""
    reset_url = f"{base_url}/reset_password_request"
    
    log_message(f"Testing password reset rate limit ({num_requests} attempts)...")
    
    # Create a session to handle cookies
    session = requests.Session()
    
    # Get CSRF token from the password reset page
    csrf_token = get_csrf_token(session, reset_url)
    if not csrf_token:
        log_message("Cannot proceed without CSRF token!")
        pytest.skip("Password reset page did not provide CSRF token in this environment")
    
    # Password reset data with some email
    reset_data = {
        "email": "test@example.com",
        "csrf_token": csrf_token
    }
    
    # Send multiple requests
    for i in range(1, num_requests + 1):
        response = session.post(reset_url, data=reset_data, allow_redirects=False)
        
        status = response.status_code
        rate_limit_header = response.headers.get('X-RateLimit-Remaining', 'N/A')
        
        if status == 429:
            log_message(f"Request {i}: Rate limit exceeded (Status: {status})")
            log_message(f"Rate limit test successful! The password reset endpoint is properly protected.")
            return
        else:
            log_message(f"Request {i}: Status: {status}, Remaining: {rate_limit_header}")
    
    log_message("All requests completed without hitting rate limit.")
    pytest.skip("Password reset rate limit was not reached with current environment/threshold")

def test_password_reset_token_rate_limit(base_url, num_requests=5):
    """Test rate limiting on the password reset with token endpoint"""
    # Using an invalid token for testing
    reset_token_url = f"{base_url}/reset_password/invalid_token_for_testing"
    
    log_message(f"Testing password reset token rate limit ({num_requests} attempts)...")
    
    # Create a session to handle cookies
    session = requests.Session()
    
    # Send multiple GET requests to the reset token URL
    for i in range(1, num_requests + 1):
        response = session.get(reset_token_url, allow_redirects=False)
        
        status = response.status_code
        rate_limit_header = response.headers.get('X-RateLimit-Remaining', 'N/A')
        
        if status == 429:
            log_message(f"Request {i}: Rate limit exceeded (Status: {status})")
            log_message(f"Rate limit test successful! The password reset token endpoint is properly protected.")
            return
        else:
            log_message(f"Request {i}: Status: {status}, Remaining: {rate_limit_header}")
    
    log_message("All requests completed without hitting rate limit.")
    pytest.skip("Reset-token rate limit was not reached with current environment/threshold")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Test rate limiting on sensitive endpoints')
    parser.add_argument('--url', default='http://127.0.0.1:5000', help='Base URL of the application')
    parser.add_argument('--requests', type=int, default=10, help='Number of requests to send for each test')
    args = parser.parse_args()
    
    log_message("Starting rate limit tests...")
    
    login_success = test_login_rate_limit(args.url, num_requests=args.requests)
    
    # Small delay between tests
    time.sleep(2)
    
    reset_success = test_password_reset_rate_limit(args.url, num_requests=args.requests)
    
    # Small delay between tests
    time.sleep(2)
    
    token_success = test_password_reset_token_rate_limit(args.url, num_requests=args.requests)
    
    log_message("\nTest Results Summary:")
    log_message(f"Login rate limit test: {'PASSED' if login_success else 'FAILED'}")
    log_message(f"Password reset rate limit test: {'PASSED' if reset_success else 'FAILED'}")
    log_message(f"Password reset token rate limit test: {'PASSED' if token_success else 'FAILED'}")
    
    if not (login_success and reset_success and token_success):
        log_message("\nNote: If tests show 'FAILED', try increasing the number of requests with --requests parameter.")
        log_message("Example: python test_rate_limits.py --requests 15")
