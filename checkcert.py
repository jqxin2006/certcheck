"""
This script is leveraging the function provided by
https://www.ssllabs.com/ssltest/analyze.html to retrive the
score of the given domain/ip and all security issues
identified. The script parses the html content to retrive
the score, warnings and errors. It depends on the the format
of https://www.ssllabs.com/ssltest/analyze.html
"""
import mechanize
import cookielib
from bs4 import BeautifulSoup
import time
import re
import socket
from struct import *
from datetime import datetime
from json import dumps
import requests
import sys
from urlparse import urlparse

# need to pass a url 
if (len(sys.argv) != 2):
    print """Usage checkcert.py target_url
        This script leverages the function provided by
        https://www.ssllabs.com/ssltest/analyze.html to retrive the
        score of the given domain/ip and all security issues
        identified.
    """
    sys.exit(-1)
else:
    target_url = sys.argv[1]

# Browser
br = mechanize.Browser()

# Cookie Jar
cj = cookielib.LWPCookieJar()
br.set_cookiejar(cj)

# Browser options
br.set_handle_equiv(True)
#br.set_handle_gzip(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)

# Follows refresh 0 but not hangs on refresh > 0
br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

# Want debugging messages?
#br.set_debug_http(True)
#br.set_debug_redirects(True)
#br.set_debug_responses(True)

# User-Agent (this is cheating, ok?)
br.addheaders = [('User-agent',
                 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:31.0)\
    Gecko/20100101 Firefox/31.0')]


def lookup(ip):
    """
    This function checks whether the given IP address is private
    or public. It returns True for private IP.
    """
    f = unpack('!I', socket.inet_pton(socket.AF_INET, ip))[0]
    private = (
        [2130706432, 4278190080],
        # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [3232235520, 4294901760],
        # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [2886729728, 4293918720],
        # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [167772160,  4278190080],
        # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    )
    for net in private:
        if (f & net[1] == net[0]):
            return True
    return False


def try_one_score(test_url):
    """
    Try to get the score, warnings and errors of the given domain
    and IP address. If the result is ready, it returns a tuple
    (score, issues). If the result is not ready, it returns "none"
    """
    r = br.open(test_url)
    html = r.read()
    result_urls = []
    base_url = "https://www.ssllabs.com/ssltest/"
    multiple_links = False

    soup = BeautifulSoup(html)
    rating = soup.find_all("div", attrs={"class": re.compile("rating_")})
    # the score is the div with class as rating_r or rating_a
    
    if len(rating) == 0:
        return "none"

    if len(rating) == 1:
        score = rating[0].text
        score = score.strip()
        issues = get_issues(html)
        return (test_url, score, issues)

def clear_cache(test_url):
    """
    Try to clear the cache if the result is ready. 
    """
    r = br.open(test_url)
    html = r.read()
    result_urls = []
    base_url = "https://www.ssllabs.com/ssltest/"
    multiple_links = False

    soup = BeautifulSoup(html)
    rating = soup.find_all("div", attrs={"class": re.compile("rating_")})
    # the score is the div with class as rating_r or rating_a
    
    if len(rating) == 0:
        return True

    # the score is ready
    if len(rating) == 1:
        req = br.click_link(text='Clear cache')
        br.open(req)
        time.sleep(5)
    


def get_issues(html):
    """
    This function parse the HTML response and extract the warnings and
    errors. The result is returned as a list.
    """
    soup = BeautifulSoup(html)
    issues = []
    # make sure that the response is valid with checking for score div
    rating = soup.find_all("div", attrs={"class": re.compile("rating_")})
    if len(rating) == 0:
        return []
    # all errors are divs with class=errorBox
    errors = soup.find_all("div", attrs={"class": "errorBox"})
    for error in errors:
        # ignore the client error of Apple browser
        m = re.search('discovered bug in Apple', error.text.strip())
        if m is not None:
            pass
        else:
            # ignore the part following \r\n
            issues.append(error.text.strip().split("\r\n")[0])
    # all warnings are divs with class=warningBox
    warnings = soup.find_all("div", attrs={"class": "warningBox"})
    for warning in warnings:
        # ignore the part following \r\n
        issues.append(warning.text.strip().split("\r\n")[0])
    return issues


def get_score(test_url):
    """
    This function get the score for given domain and IP. It keeps
    query the URL until the valid response is ready. If the response
    is not ready, the process sleeps for 25 seconds before
    trying again. If there is still no result after 10 attempts, it
    gives up and returns "none"

    """
    # track the attempt
    attempt = 0
    # Try MAX_ATTEMPTS before giving up
    MAX_ATTEMPTS = 10
    # the process sleep SLEEP_TIME seconds before trying again
    SLEEP_TIME = 25
    score = "none"
    score = try_one_score(test_url)
  
    while score == "none":
        attempt += 1
        time.sleep(SLEEP_TIME)
        score = try_one_score(test_url)
        if attempt > MAX_ATTEMPTS:
            break
    return score

def get_scores(domain, ip):
    """
    This function get the scores for given domain and IP. Sometimes, it
    might be able to get more than one scores. 

    """
    # first request to clear the cache
    base_url = "https://www.ssllabs.com/ssltest/analyze.html?d=%s&hideResults=on&clearCache=on"
    test_url = base_url % (domain)  
    r = br.open(test_url)
    html = r.read()

    # the second request to check the score 
    base_url = "https://www.ssllabs.com/ssltest/analyze.html?d=%s&s=%s&hideResults=on&ignoreMismatch=on"
    test_url = base_url % (domain, ip)  

    r = br.open(test_url)
    html = r.read()

    results = []
    result_urls = []
    base_url = "https://www.ssllabs.com/ssltest/"
    multiple_links = False

    soup = BeautifulSoup(html)


    rating = soup.find_all("div", attrs={"class": re.compile("rating_")})
    # the score is the div with class as rating_r or rating_a
    
    if len(rating) > 0:
        clear_cache(test_url)
        score = get_score(test_url)
        results.append(score)
        return results

    # Still working on the testing
    if re.search("Please wait\.\.\.", html) is not None:
        score = get_score(test_url)
        results.append(score)
        return results

    for a in soup.findAll('a'):
        if 'analyze.html' in a['href'] and 'clearCache' not in a['href']:
            result_urls.append("%s%s" % (base_url,a['href']))
            multiple_links = True
    print result_urls

    if multiple_links is True:
        for the_url in result_urls:
            clear_cache(the_url)
            score = get_score(the_url)
            results.append(score)
    return results


def get_public_cert_score(the_url):
    """
    This function should be used to get the certificate score
    and issues by given public domain. It returns {} for private
    IP and other errors. It returns a dictionary with score and
    other information for successful result.
    """
    result = {}
    #pare url to get the domain 
    parsed_uri = urlparse(the_url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    
    try:
        ip = socket.gethostbyname(domain)
    except:
        #in case the domain can not be resloved, return {}
        return result
       
    #only check for public IP
    if lookup(ip) is False:
        score_issues = get_scores(domain, ip)
    else:
        pass
    return score_issues


print dumps(get_public_cert_score(target_url))

