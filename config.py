# Google Safe Browsing API
# Get your free API key from: https://console.cloud.google.com/
# Enable the "Safe Browsing API" for your project.
GOOGLE_SAFE_BROWSING_API_KEY = "" #enter your API key here

# Known Brands for Typosquatting Detection
KNOWN_BRANDS = [
    'orange', 'mascom', 'btc', 'botswana', 'botswanna',
    'fnb', 'firstnational',
    'standard', 'stanbic', 'bancabc', 'bankgaborone', 'myzaka', 'orangemoney',
    'choppies', 'sefalana', 'picknpay', 'spar',
    'shell', 'engen', 'caltex', 'total'
]

# TLD Categorization
HIGH_RISK_TLDS = {'.xyz', '.top', '.club', '.gq', '.cf', '.ml', '.tk', '.pp.ua', '.icu', '.country', '.science', '.buzz', '.info', '.online'}
LOW_RISK_TLDS = {'.com', '.org', '.net', '.co.bw', '.bw', '.uk', '.de', '.ca', '.au', '.edu', '.gov'}  # Example of common, trusted TLDs

# Company to Social Media Mapping
COMPANY_PAGES = {
    # Telecommunications & ISP
    'orange': 'https://www.facebook.com/OrangeBotswana',
    'mascom': 'https://www.facebook.com/MascomBotswana',
    'btc': 'https://www.facebook.com/BTCLimited',
    'botswana telecoms': 'https://www.facebook.com/BTCLimited',
    'botswanna telecoms': 'https://www.facebook.com/BTCLimited',

    # Banks & Financial Institutions
    'fnb': 'https://www.facebook.com/FNBBotswana',
    'first national bank': 'https://www.facebook.com/FNBBotswana',
    'standard bank': 'https://www.facebook.com/StandardBankBW',
    'stanbic': 'https://www.facebook.com/StandardBankBW',
    'bancabc': 'https://www.facebook.com/BancABCBotswana',
    'bank gaborone': 'https://www.facebook.com/BankGaborone',
    'myzaka': 'https://www.facebook.com/MyZakaBW',
    'orangemoney': 'https://www.facebook.com/OrangeMoneyBotswana',

    # Retail & Supermarkets
    'choppies': 'https://www.facebook.com/ChoppiesStores',
    'sefalana': 'https://www.facebook.com/SefalanaBotswana',
    'pick n pay': 'https://www.facebook.com/PicknPayBotswana',
    'spar': 'https://www.facebook.com/SPARBotswana',

    # Fuel Stations & Energy
    'shell': 'https://www.facebook.com/ShellBotswana',
    'engen': 'https://www.facebook.com/EngenBotswana',
    'caltex': 'https://www.facebook.com/CaltexBotswana',
    'total': 'https://www.facebook.com/TotalBotswana',
}