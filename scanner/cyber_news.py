from django.shortcuts import render
import feedparser
from bs4 import BeautifulSoup
import requests
from datetime import datetime

def fetch_cyber_news():
    # पॉपुलर साइबर सिक्योरिटी RSS Feeds
    feeds = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/"
    ]
    
    parsed_news = []
    
    for url in feeds:
        feed = feedparser.parse(url)
        for entry in feed.entries[:6]: # हर सोर्स से टॉप 6 ख़बरें
            # HTML कंटेंट से इमेज निकालने के लिए BeautifulSoup का उपयोग
            summary_html = entry.get('summary', '') or entry.get('description', '')
            soup = BeautifulSoup(summary_html, 'html.parser')
            
            # इमेज ढूंढने की कोशिश (अगर RSS में मौजूद हो)
            img_tag = soup.find('img')
            image_url = img_tag['src'] if img_tag else None
            
            # अगर इमेज नहीं मिली, तो एक डिफ़ॉल्ट साइबर टेक इमेज सेट करें
            if not image_url:
                image_url = "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?q=80&w=500&auto=format&fit=crop"

            # क्लीन टेक्स्ट निकालना
            clean_text = soup.get_text()[:150] + "..." if len(soup.get_text()) > 150 else soup.get_text()
            
            # तारीख को अच्छे फॉर्मेट में बदलना
            published = entry.get('published', '')
            try:
                # RSS डेट्स को रीडेबल बनाना
                date_parsed = entry.published_parsed
                published_formatted = datetime(*date_parsed[:6]).strftime('%d %b %Y, %H:%M')
            except:
                published_formatted = published

            parsed_news.append({
                'title': entry.title,
                'link': entry.link,
                'summary': clean_text,
                'image': image_url,
                'source': 'The Hacker News' if 'hackersnews' in url else 'BleepingComputer',
                'published': published_formatted
            })
            
    # लेटेस्ट ख़बरों को ऊपर रखने के लिए (अगर सॉर्ट करना चाहें)
    return parsed_news

def cyber_dashboard(request):
    # लाइव न्यूज़ फेच करें
    news_feed = fetch_cyber_news()
    
    context = {
        'news_feed': news_feed,
        'last_updated': datetime.now().strftime('%H:%M:%S')
    }
    return render(request, 'dashboard.html', context)