import ipaddress
import urllib
import urllib.request
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tldextract import extract
from whois import whois
import regex
import ssl
import socket
import requests
import re
import datetime
import dns.resolver
import sys
import joblib
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import make_classification
from sklearn import metrics
import CSVReader
import time


def domain_registration(url):
    try:
        w = whois.whois(url)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp[0]-updated[0]).days
        if(length<=365):
            return 1
        else:
            return -1
    except:
        return -1
       
def age_of_domain(url):
    try:
        w = whois(url)
        start_date = w.creation_date
        current_date = datetime.datetime.now()
        age =(current_date-start_date[0]).days
        if(age>=180): 
            return -1
        else:
            return 1
    except Exception as e:
        return 1
        
def web_traffic(url):
    try:
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
   
    except TypeError:
        return 0
    rank=int(rank)
    
    if rank < 100000:
        return -1
    elif rank == 100000:
        return 0
    else:
        return 1

def numberoflinks(url):      
    if 'http' not in url and 'https' not in url:
        url='http://'+url
    try: 
        response = requests.get(url)
    except:
        response = ""
    try:
        number_of_links = len(re.findall(r"<a href=", response.text)) 
        if number_of_links == 0:         
            return 1    
        elif number_of_links>0 and number_of_links<=2:
            return 0
        else:
            return -1
    except:
        return 0
        
def forwarding(url):
    if 'http' not in url and 'https' not in url:
        url='http://'+url
    try: 
        response = requests.get(url)
    except:
        response = ""
    if response == "":
        return 1
    else:
        if len(response.history) <=1:
            return -1
        elif (len(response.history)>=2 and len(response.history)<4):
            return 0
        else:
            return 1
def mouseOver(url):
    if 'http' not in url and 'https' not in url:
        url='http://'+url
    try: 
        response = requests.get(url)
    except:
        response = ""
    if response == "" :
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return -1



def rightClick(url):
    if 'http' not in url and 'https' not in url:
        url='http://'+url
    try: 
        response = requests.get(url)
    except:
        response = ""
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 1
        else:
            return -1
            
def SSLfinal_State(url):
    try:
#check wheather contains https       
        if(regex.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0
#getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] +  + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0] 
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        
#getting age of certificate
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear-startingYear
        
#checking final conditions
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ):
            return -1 #legitimate
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 0 #suspicious
        else:
            return 1 #phishing
        
    except Exception as e:
        
        return -1
def popUpwindow(url):
    if 'http' not in url and 'https' not in url:
        url='http://'+url
    try: 
        response = requests.get(url)
    except:
        response = ""
    try:         
        if re.findall(r"alert\(", response.text):            
            return 1         
        else:             
            return -1   
    except:
        return -1
        
        
def dns_record(url):
    try:
        answers=dns.resolver.query(url)
        for rdata in answers:
            return 0
    except:
        return 1




def abnormal_url(url):
    if 'http' not in url and 'https' not in url:
        url='http://'+url
    domain = urlparse(url).netloc
    if url.find(domain)==-1:
        return 1
    else:
        return -1
  

if __name__=="__main__":
    start_time = time.time()
    res = sys.argv[1]
    features = []
    res = res.split(",")
    url = res[0].replace("\/","/")
    #print(url)
    res = res[1:]
    path='C:/xampp/htdocs/C_E_NEW_PSO'
    res = list(map(lambda x:int(x),res))
    #res = [-1, 0, -1, -1, 1, -1, 1, 1, -1, -1, -1, 1, 1, 1, -1, -1, -1]
    #url = 'www.google.com'
    features = [res[0],res[1],res[2],res[3],res[4],res[5],res[6],SSLfinal_State(url),res[7],res[8],res[9],res[10],res[11],res[12],abnormal_url(url),forwarding(url),mouseOver(url),popUpwindow(url),res[13],age_of_domain(url),web_traffic(url),numberoflinks(url)]
    #print(features)
    clf = joblib.load(path+'/random_forest.joblib')
    pred = clf.predict([features])
    print(int(pred[0]))
    print(time.time() - start_time)
    
        
