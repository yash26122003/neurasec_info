import streamlit as st
import pandas as pd
import time
import json
from website_info_extractor import WebsiteInfoExtractor

# Set page configuration
st.set_page_config(
    page_title="Website Information Extractor",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
    }
    .subheader {
        font-size: 1.5rem;
        color: #1976D2;
        padding-top: 10px;
    }
    .info-box {
        background-color: #f0f2f6;
        border-radius: 5px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .stProgress > div > div > div {
        background-color: #1E88E5;
    }
    .highlight {
        background-color: #e6f3ff;
        padding: 5px;
        border-radius: 3px;
    }
</style>
""", unsafe_allow_html=True)

def main():
    # Title and description
    st.markdown('<p class="main-header">Website Information Extractor</p>', unsafe_allow_html=True)
    st.markdown("""
    This tool extracts comprehensive information about a website including domain details, 
    IP addresses, DNS records, WHOIS data, hosting information, and more.
    """)
    
    # Input section
    st.markdown("### Enter a website to analyze")
    col1, col2 = st.columns([3, 1])
    with col1:
        url = st.text_input("Enter URL or domain (e.g., example.com):", "")
    with col2:
        analyze_button = st.button("Analyze Website")
    
    # When analyze button is clicked and URL is provided
    if analyze_button and url:
        run_analysis(url)

def run_analysis(url):
    # Analysis progress
    progress = st.progress(0)
    status_text = st.empty()
    
    try:
        # Initialize the extractor
        status_text.text("Initializing...")
        progress.progress(10)
        extractor = WebsiteInfoExtractor(url, verbose=False)
        
        # Extract information with progress updates
        status_text.text("Extracting IP addresses...")
        progress.progress(20)
        ip_addresses = extractor.extract_ip_addresses()
        
        status_text.text("Extracting DNS records...")
        progress.progress(30)
        dns_records = extractor.extract_dns_records()
        
        status_text.text("Extracting WHOIS data...")
        progress.progress(40)
        whois_data = extractor.extract_whois_data()
        
        status_text.text("Extracting hosting information...")
        progress.progress(50)
        hosting_info = extractor.extract_hosting_info()
        
        status_text.text("Extracting ASN information...")
        progress.progress(60)
        asn_info = extractor.extract_asn_info()
        
        status_text.text("Checking blacklist status...")
        progress.progress(70)
        blacklist_status = extractor.check_blacklist_status()
        
        status_text.text("Finding related domains...")
        progress.progress(80)
        related_domains = extractor.find_related_domains()
        
        status_text.text("Extracting SSL information...")
        progress.progress(90)
        ssl_info = extractor.extract_ssl_info()
        
        # Complete
        progress.progress(100)
        status_text.text("Analysis completed!")
        time.sleep(1)
        status_text.empty()
        progress.empty()
        
        # Get all results
        results = extractor.results
        
        # Display the results
        display_results(results)
        
    except Exception as e:
        progress.empty()
        status_text.empty()
        st.error(f"Error: {str(e)}")

def display_results(results):
    st.markdown("## Analysis Results")
    
    # Create tabs for different categories of information
    tabs = st.tabs([
        "Overview", 
        "DNS Records", 
        "WHOIS Data", 
        "Hosting & ASN", 
        "SSL Certificate", 
        "Blacklist Status", 
        "Related Domains"
    ])
    
    # Overview Tab
    with tabs[0]:
        st.markdown('<p class="subheader">Domain and IP Address Information</p>', unsafe_allow_html=True)
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<div class="info-box">', unsafe_allow_html=True)
            st.markdown(f"**Domain:** {results['domain']}")
            if results['ipv4_addresses']:
                st.markdown(f"**IPv4 Addresses:**")
                for ip in results['ipv4_addresses']:
                    st.markdown(f"- {ip}")
            else:
                st.markdown("**IPv4 Addresses:** None found")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<div class="info-box">', unsafe_allow_html=True)
            if results['ipv6_addresses']:
                st.markdown(f"**IPv6 Addresses:**")
                for ip in results['ipv6_addresses']:
                    st.markdown(f"- {ip}")
            else:
                st.markdown("**IPv6 Addresses:** None found")
            st.markdown('</div>', unsafe_allow_html=True)
    
    # DNS Records Tab
    with tabs[1]:
        st.markdown('<p class="subheader">DNS Records</p>', unsafe_allow_html=True)
        if results['dns_records']:
            for record_type, records in results['dns_records'].items():
                with st.expander(f"{record_type} Records"):
                    for i, record in enumerate(records):
                        st.code(record)
        else:
            st.info("No DNS records found.")
    
    # WHOIS Data Tab
    with tabs[2]:
        st.markdown('<p class="subheader">WHOIS Information</p>', unsafe_allow_html=True)
        if results['whois_data']:
            whois_data = results['whois_data']
            # Create two columns for better layout
            col1, col2 = st.columns(2)
            
            # Process each key-value pair from WHOIS data
            whois_items = list(whois_data.items())
            mid_point = len(whois_items) // 2
            
            with col1:
                for key, value in whois_items[:mid_point]:
                    st.markdown(f"**{key.replace('_', ' ').title()}:**")
                    if isinstance(value, list):
                        for item in value:
                            st.markdown(f"- {item}")
                    else:
                        st.markdown(f"{value}")
                    st.markdown("---")
            
            with col2:
                for key, value in whois_items[mid_point:]:
                    st.markdown(f"**{key.replace('_', ' ').title()}:**")
                    if isinstance(value, list):
                        for item in value:
                            st.markdown(f"- {item}")
                    else:
                        st.markdown(f"{value}")
                    st.markdown("---")
        else:
            st.info("No WHOIS data available.")
    
    # Hosting & ASN Tab
    with tabs[3]:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown('<p class="subheader">Hosting Information</p>', unsafe_allow_html=True)
            hosting = results['hosting_info']
            st.markdown('<div class="info-box">', unsafe_allow_html=True)
            st.markdown(f"**Provider:** {hosting.get('provider', 'Unknown')}")
            st.markdown(f"**Server Location:** {hosting.get('server_location', 'Unknown')}")
            st.markdown(f"**Server Type:** {hosting.get('server_type', 'Unknown')}")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with col2:
            st.markdown('<p class="subheader">ASN Information</p>', unsafe_allow_html=True)
            asn = results['asn_info']
            if asn:
                st.markdown('<div class="info-box">', unsafe_allow_html=True)
                for key, value in asn.items():
                    st.markdown(f"**{key.replace('_', ' ').title()}:** {value}")
                st.markdown('</div>', unsafe_allow_html=True)
            else:
                st.info("No ASN information available.")
    
    # SSL Certificate Tab
    with tabs[4]:
        st.markdown('<p class="subheader">SSL Certificate</p>', unsafe_allow_html=True)
        
        if "ssl_info" in results:
            ssl = results["ssl_info"]
            st.markdown('<div class="info-box">', unsafe_allow_html=True)
            st.markdown(f"**Has SSL:** {'✅ Yes' if ssl.get('has_ssl', False) else '❌ No'}")
            
            if ssl.get('has_ssl', False):
                st.markdown(f"**Issuer:** {ssl.get('issuer', 'Unknown')}")
                st.markdown(f"**Valid From:** {ssl.get('valid_from', 'Unknown')}")
                st.markdown(f"**Valid Until:** {ssl.get('valid_until', 'Unknown')}")
                
                if ssl.get('san_domains'):
                    st.markdown("**SAN Domains:**")
                    for domain in ssl.get('san_domains', []):
                        st.markdown(f"- {domain}")
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("No SSL information available.")
    
    # Blacklist Status Tab
    with tabs[5]:
        st.markdown('<p class="subheader">Blacklist Status</p>', unsafe_allow_html=True)
        
        blacklist = results["blacklist_status"]
        st.markdown('<div class="info-box">', unsafe_allow_html=True)
        
        domain_status = "❌ Blacklisted" if blacklist.get('domain_blacklisted', False) else "✅ Not Blacklisted"
        ip_status = "❌ Blacklisted" if blacklist.get('ip_blacklisted', False) else "✅ Not Blacklisted"
        
        st.markdown(f"**Domain Status:** {domain_status}")
        st.markdown(f"**IP Status:** {ip_status}")
        
        if blacklist.get('blacklists'):
            st.markdown("**Found in Blacklists:**")
            for bl in blacklist.get('blacklists', []):
                st.markdown(f"- {bl}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Related Domains Tab
    with tabs[6]:
        st.markdown('<p class="subheader">Related Domains</p>', unsafe_allow_html=True)
        
        if results["related_domains"]:
            col1, col2 = st.columns(2)
            domains = results["related_domains"]
            mid_point = len(domains) // 2
            
            with col1:
                for domain in domains[:mid_point]:
                    st.markdown(f"- {domain}")
            
            with col2:
                for domain in domains[mid_point:]:
                    st.markdown(f"- {domain}")
        else:
            st.info("No related domains found.")
    
    # Add an option to export results as JSON
    st.markdown("## Export Results")
    if st.button("Export as JSON"):
        # Convert results to JSON string
        json_results = json.dumps(results, indent=4)
        # Create a download button
        st.download_button(
            label="Download JSON",
            data=json_results,
            file_name=f"{results['domain']}_analysis.json",
            mime="application/json"
        )

if __name__ == "__main__":
    main() 