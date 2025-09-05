import pygame
import sys
import webbrowser
import time
from datetime import datetime

# Initialize pygame
pygame.init()
pygame.font.init()

# Screen dimensions
WIDTH, HEIGHT = 1000, 700
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("HCO OSINT Tool - Advanced Intelligence Platform")

# Colors
DARK_BG = (10, 15, 30)
LIGHT_BG = (20, 25, 40)
HIGHLIGHT = (0, 100, 200)
ACCENT = (0, 150, 255)
WHITE = (220, 220, 220)
GRAY = (150, 150, 150)
GREEN = (0, 200, 100)
RED = (220, 50, 50)
YELLOW = (220, 180, 60)
BLUE = (30, 70, 150)
PURPLE = (150, 60, 220)
ORANGE = (255, 150, 50)

# Fonts
title_font = pygame.font.SysFont("arial", 32, bold=True)
header_font = pygame.font.SysFont("arial", 24, bold=True)
main_font = pygame.font.SysFont("arial", 18)
small_font = pygame.font.SysFont("arial", 14)
large_font = pygame.font.SysFont("arial", 48, bold=True)

# Tool states
UNLOCKED = 0
COUNTDOWN = 1
LOCKED = 2
SUCCESS = 3

# Initialize tool state
tool_state = LOCKED
countdown_time = 10  # seconds
start_time = 0
entered_code = ""
subscription_message = "Tool is locked! Subscribe and click the bell icon to unlock!"
youtube_url = "https://www.youtube.com/channel/UC9P7GSPQpPxjc6Uu-cx-F8w"

# OSINT data (simulated)
domain_data = {
    "whois": {
        "Registrar": "NameCheap, Inc.",
        "Creation Date": "2018-05-15",
        "Expiration Date": "2024-05-15",
        "Name Servers": ["ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"],
        "Registrant": "REDACTED FOR PRIVACY",
        "Admin Contact": "REDACTED FOR PRIVACY",
        "Technical Contact": "REDACTED FOR PRIVACY",
        "Status": "clientTransferProhibited"
    },
    "dns": {
        "A": ["192.0.2.44", "192.0.2.45"],
        "AAAA": ["2001:0db8:85a3:0000:0000:8a2e:0370:7334"],
        "MX": ["10 mail.example.com", "20 mail2.example.com"],
        "TXT": ["v=spf1 include:_spf.example.com ~all", "google-site-verification=abc123"],
        "CNAME": ["www -> example.com", "blog -> hosting-platform.com"],
        "NS": ["ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"]
    },
    "subdomains": ["www", "mail", "blog", "dev", "api", "test", "shop", "support", "forum", "news"],
    "ssl": {
        "Issuer": "Let's Encrypt",
        "Expiration": "2023-12-01",
        "Algorithm": "SHA-256 with RSA",
        "Key Size": "2048 bits"
    },
    "technologies": {
        "Web Server": "nginx/1.18.0",
        "Programming Language": "PHP 8.1.10",
        "JavaScript Framework": "React 18.2.0",
        "Database": "MySQL 8.0.30",
        "CMS": "WordPress 6.0.2"
    }
}

social_media_data = {
    "twitter": {
        "handle": "@examplecorp",
        "followers": "12.5K",
        "following": "327",
        "joined": "March 2015",
        "activity": "High (3-5 tweets per day)",
        "last_tweet": "2023-05-15 14:23:45 UTC",
        "top_hashtags": ["#tech", "#innovation", "#business"]
    },
    "facebook": {
        "handle": "ExampleCorporation",
        "followers": "45.2K",
        "likes": "38.7K",
        "page_created": "2014-08-12",
        "page_category": "Technology Company",
        "verification_status": "Verified"
    },
    "linkedin": {
        "handle": "example-corporation",
        "employees": "250-500",
        "industry": "Technology",
        "company_size": "251-500 employees",
        "founded": "2013",
        "specialties": "Software Development, Cloud Computing, AI Solutions"
    },
    "instagram": {
        "handle": "@examplecorp",
        "followers": "23.4K",
        "following": "512",
        "posts": "1,234",
        "engagement_rate": "4.2%"
    }
}

person_data = {
    "name": "John A. Smith",
    "email": "john.smith@example.com",
    "phone": "+1 (555) 123-4567",
    "locations": ["New York, NY", "San Francisco, CA", "London, UK"],
    "employment": ["Example Corp (Current) - Senior Developer", "Previous Company Inc - Software Engineer"],
    "education": ["University of Technology - Computer Science (2010-2014)"],
    "social_media": {
        "twitter": "@johnsmith (2.3K followers)",
        "linkedin": "john-smith-abc123 (500+ connections)",
        "github": "johnsmith (24 repositories)"
    },
    "skills": ["Python", "JavaScript", "React", "Node.js", "Cloud Architecture"],
    "recent_activity": {
        "twitter": "Active (5 tweets this week)",
        "github": "Active (2 commits this week)",
        "linkedin": "Active (Shared 1 post this week)"
    }
}

image_analysis_data = {
    "basic_info": {
        "File Type": "JPEG",
        "Dimensions": "1200x800 pixels",
        "File Size": "450 KB",
        "Color Space": "RGB",
        "Resolution": "72 dpi"
    },
    "exif_data": {
        "Camera Model": "iPhone 12 Pro",
        "Date Taken": "2023-05-12 14:23:45 UTC",
        "Exposure": "1/60 sec",
        "Aperture": "f/1.6",
        "ISO": "100",
        "Focal Length": "4.2 mm",
        "Software": "Adobe Photoshop 2023"
    },
    "geolocation": {
        "Estimated Location": "New York, NY (85% confidence)",
        "GPS Coordinates": "40.7128° N, 74.0060° W",
        "Landmarks": "Central Park, Empire State Building"
    },
    "advanced_analysis": {
        "Face Detection": "3 faces identified",
        "Objects Detected": ["Person", "Building", "Car", "Tree"],
        "Color Distribution": "Dominant colors: #3A5FCD (blue), #228B22 (green), #8B4513 (brown)",
        "Edit Detection": "High probability of manipulation (85%)"
    }
}

# UI Elements
class Button:
    def __init__(self, x, y, width, height, text, color=HIGHLIGHT, hover_color=ACCENT, text_color=WHITE):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.color = color
        self.hover_color = hover_color
        self.text_color = text_color
        self.is_hovered = False
        
    def draw(self, surface):
        color = self.hover_color if self.is_hovered else self.color
        pygame.draw.rect(surface, color, self.rect, border_radius=8)
        pygame.draw.rect(surface, WHITE, self.rect, 2, border_radius=8)
        
        text_surf = main_font.render(self.text, True, self.text_color)
        text_rect = text_surf.get_rect(center=self.rect.center)
        surface.blit(text_surf, text_rect)
        
    def check_hover(self, pos):
        self.is_hovered = self.rect.collidepoint(pos)
        return self.is_hovered
        
    def check_click(self, pos, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            return self.rect.collidepoint(pos)
        return False

class InputBox:
    def __init__(self, x, y, width, height, text='', placeholder='Enter text...'):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.placeholder = placeholder
        self.active = False
        self.color = LIGHT_BG
        
    def handle_event(self, event):
        if event.type == pygame.MOUSEBUTTONDOWN:
            self.active = self.rect.collidepoint(event.pos)
            self.color = WHITE if self.active else LIGHT_BG
        if event.type == pygame.KEYDOWN:
            if self.active:
                if event.key == pygame.K_RETURN:
                    return self.text
                elif event.key == pygame.K_BACKSPACE:
                    self.text = self.text[:-1]
                else:
                    self.text += event.unicode
        return None
        
    def draw(self, surface):
        pygame.draw.rect(surface, self.color, self.rect, border_radius=5)
        pygame.draw.rect(surface, WHITE, self.rect, 2, border_radius=5)
        
        if self.text:
            text_surf = main_font.render(self.text, True, DARK_BG if self.active else WHITE)
        else:
            text_surf = main_font.render(self.placeholder, True, GRAY)
            
        surface.blit(text_surf, (self.rect.x + 10, self.rect.y + 10))

class Tab:
    def __init__(self, x, y, width, height, text, color=BLUE):
        self.rect = pygame.Rect(x, y, width, height)
        self.text = text
        self.active = False
        self.color = color
        
    def draw(self, surface):
        color = self.color if self.active else LIGHT_BG
        pygame.draw.rect(surface, color, self.rect, border_radius=5)
        pygame.draw.rect(surface, WHITE, self.rect, 2, border_radius=5)
        
        text_surf = main_font.render(self.text, True, WHITE)
        text_rect = text_surf.get_rect(center=self.rect.center)
        surface.blit(text_surf, text_rect)
        
    def check_click(self, pos, event):
        if event.type == pygame.MOUSEBUTTONDOWN and event.button == 1:
            if self.rect.collidepoint(pos):
                self.active = True
                return True
        return False

# Create UI elements
search_box = InputBox(50, 20, 300, 40, '', 'Enter domain, username, or keyword...')
search_button = Button(360, 20, 100, 40, "Search", GREEN, (0, 230, 120))

tabs = [
    Tab(50, 80, 120, 40, "Domain Info", BLUE),
    Tab(180, 80, 120, 40, "Social Media", PURPLE),
    Tab(310, 80, 120, 40, "People Search", ORANGE),
    Tab(440, 80, 120, 40, "Image Analysis", GREEN),
    Tab(570, 80, 120, 40, "Metadata", RED),
    Tab(700, 80, 120, 40, "Network", YELLOW)
]
tabs[0].active = True

action_buttons = [
    Button(800, 20, 150, 40, "Generate Report", PURPLE, (180, 80, 220)),
    Button(800, 80, 150, 40, "Save Results", GREEN, (0, 230, 120)),
    Button(800, 140, 150, 40, "Export Data", BLUE, (30, 170, 255))
]

subscribe_button = Button(WIDTH//2 - 100, HEIGHT//2 + 50, 200, 50, "Subscribe on YouTube", RED, (255, 50, 50))
unlock_button = Button(WIDTH//2 - 100, HEIGHT//2 + 120, 200, 50, "Unlock Tool", GREEN, (0, 230, 120))

# Main loop
clock = pygame.time.Clock()
current_tab = "Domain Info"

def draw_locked_screen():
    # Draw background
    screen.fill(DARK_BG)
    
    # Draw lock icon
    lock_rect = pygame.Rect(WIDTH//2 - 50, HEIGHT//2 - 150, 100, 100)
    pygame.draw.rect(screen, RED, lock_rect, border_radius=15)
    pygame.draw.rect(screen, WHITE, lock_rect, 3, border_radius=15)
    
    # Draw lock shape
    pygame.draw.rect(screen, WHITE, (WIDTH//2 - 20, HEIGHT//2 - 130, 40, 50), border_radius=5)
    pygame.draw.circle(screen, WHITE, (WIDTH//2, HEIGHT//2 - 105), 15, 3)
    
    # Draw message
    message = header_font.render("TOOL LOCKED", True, RED)
    screen.blit(message, (WIDTH//2 - message.get_width()//2, HEIGHT//2 - 200))
    
    instruction = main_font.render(subscription_message, True, WHITE)
    screen.blit(instruction, (WIDTH//2 - instruction.get_width()//2, HEIGHT//2 - 30))
    
    # Draw buttons
    subscribe_button.draw(screen)
    
    # Draw footer
    pygame.draw.rect(screen, LIGHT_BG, (0, HEIGHT - 30, WIDTH, 30))
    footer_text = small_font.render("HCO OSINT Tool v2.0 | © 2023 Hackers Colony Official | For educational purposes only", True, WHITE)
    screen.blit(footer_text, (WIDTH // 2 - footer_text.get_width() // 2, HEIGHT - 25))

def draw_countdown_screen():
    # Draw background
    screen.fill(DARK_BG)
    
    # Calculate remaining time
    elapsed = time.time() - start_time
    remaining = max(0, countdown_time - elapsed)
    
    # Draw countdown
    countdown_text = large_font.render(f"{int(remaining)}", True, YELLOW)
    screen.blit(countdown_text, (WIDTH//2 - countdown_text.get_width()//2, HEIGHT//2 - 50))
    
    message = header_font.render("Redirecting to YouTube...", True, WHITE)
    screen.blit(message, (WIDTH//2 - message.get_width()//2, HEIGHT//2 + 50))
    
    instruction = main_font.render("Please subscribe and click the bell icon, then return to unlock the tool", True, WHITE)
    screen.blit(instruction, (WIDTH//2 - instruction.get_width()//2, HEIGHT//2 + 100))
    
    # Draw footer
    pygame.draw.rect(screen, LIGHT_BG, (0, HEIGHT - 30, WIDTH, 30))
    footer_text = small_font.render("HCO OSINT Tool v2.0 | © 2023 Hackers Colony Official | For educational purposes only", True, WHITE)
    screen.blit(footer_text, (WIDTH // 2 - footer_text.get_width() // 2, HEIGHT - 25))
    
    return remaining <= 0

def draw_unlock_screen():
    # Draw background
    screen.fill(DARK_BG)
    
    # Draw success message
    message = header_font.render("TOOL UNLOCKED!", True, GREEN)
    screen.blit(message, (WIDTH//2 - message.get_width()//2, HEIGHT//2 - 100))
    
    # Draw HCO OSINT by Azhar in bold red inside blue box
    title_box = pygame.Rect(WIDTH//2 - 200, HEIGHT//2 - 50, 400, 80)
    pygame.draw.rect(screen, BLUE, title_box, border_radius=10)
    pygame.draw.rect(screen, WHITE, title_box, 3, border_radius=10)
    
    title_text = title_font.render("HCO OSINT by Azhar", True, RED)
    screen.blit(title_text, (WIDTH//2 - title_text.get_width()//2, HEIGHT//2 - 30))
    
    instruction = main_font.render("Press any key to continue to the tool...", True, WHITE)
    screen.blit(instruction, (WIDTH//2 - instruction.get_width()//2, HEIGHT//2 + 50))
    
    # Draw footer
    pygame.draw.rect(screen, LIGHT_BG, (0, HEIGHT - 30, WIDTH, 30))
    footer_text = small_font.render("HCO OSINT Tool v2.0 | © 2023 Hackers Colony Official | For educational purposes only", True, WHITE)
    screen.blit(footer_text, (WIDTH // 2 - footer_text.get_width() // 2, HEIGHT - 25))

def draw_domain_info():
    y_offset = 140
    # WHOIS Information
    header = header_font.render("WHOIS Information", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    for key, value in domain_data["whois"].items():
        if isinstance(value, list):
            text = main_font.render(f"{key}: {', '.join(value)}", True, WHITE)
        else:
            text = main_font.render(f"{key}: {value}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 25
    
    y_offset += 20
    # DNS Records
    header = header_font.render("DNS Records", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    for record_type, values in domain_data["dns"].items():
        text = main_font.render(f"{record_type} Records:", True, GREEN)
        screen.blit(text, (70, y_offset))
        y_offset += 25
        for value in values:
            text = small_font.render(f"  {value}", True, WHITE)
            screen.blit(text, (90, y_offset))
            y_offset += 20
    
    y_offset += 20
    # Subdomains
    header = header_font.render("Discovered Subdomains", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    subdomain_text = ", ".join(domain_data["subdomains"])
    text = main_font.render(subdomain_text, True, WHITE)
    screen.blit(text, (70, y_offset))
    
    y_offset += 40
    # SSL Certificate
    header = header_font.render("SSL Certificate Information", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    for key, value in domain_data["ssl"].items():
        text = main_font.render(f"{key}: {value}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 25
    
    y_offset += 20
    # Technologies
    header = header_font.render("Technologies Detected", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    for key, value in domain_data["technologies"].items():
        text = main_font.render(f"{key}: {value}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 25

def draw_social_media():
    y_offset = 140
    for platform, data in social_media_data.items():
        header = header_font.render(platform.capitalize(), True, YELLOW)
        screen.blit(header, (50, y_offset))
        y_offset += 30
        
        for key, value in data.items():
            text = main_font.render(f"{key.capitalize()}: {value}", True, WHITE)
            screen.blit(text, (70, y_offset))
            y_offset += 25
        y_offset += 20

def draw_people_search():
    y_offset = 140
    header = header_font.render("Person of Interest: John A. Smith", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 40
    
    for key, value in person_data.items():
        if key != "social_media":
            if isinstance(value, list):
                text = main_font.render(f"{key.capitalize()}: {', '.join(value)}", True, WHITE)
            else:
                text = main_font.render(f"{key.capitalize()}: {value}", True, WHITE)
            screen.blit(text, (70, y_offset))
            y_offset += 30
    
    y_offset += 10
    header = header_font.render("Social Media Profiles", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    for platform, handle in person_data["social_media"].items():
        text = main_font.render(f"{platform.capitalize()}: {handle}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 25
    
    y_offset += 10
    header = header_font.render("Skills & Expertise", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    skills_text = ", ".join(person_data["skills"])
    text = main_font.render(skills_text, True, WHITE)
    screen.blit(text, (70, y_offset))
    y_offset += 30
    
    header = header_font.render("Recent Activity", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 30
    
    for platform, activity in person_data["recent_activity"].items():
        text = main_font.render(f"{platform.capitalize()}: {activity}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 25

def draw_image_analysis():
    y_offset = 140
    
    for section, data in image_analysis_data.items():
        header_text = section.replace("_", " ").title()
        header = header_font.render(header_text, True, YELLOW)
        screen.blit(header, (50, y_offset))
        y_offset += 30
        
        for key, value in data.items():
            if isinstance(value, list):
                text = main_font.render(f"{key}: {', '.join(value)}", True, WHITE)
            else:
                text = main_font.render(f"{key}: {value}", True, WHITE)
            screen.blit(text, (70, y_offset))
            y_offset += 25
        y_offset += 20

def draw_metadata():
    y_offset = 140
    header = header_font.render("Document Metadata Analysis", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 40
    
    metadata = [
        ("Author", "John Smith"),
        ("Creation Date", "2023-04-15T09:32:15Z"),
        ("Last Modified", "2023-04-17T14:20:33Z"),
        ("Software", "Microsoft Word 365"),
        ("Company", "Example Corp"),
        ("Edit Time", "2 hours 15 minutes"),
        ("Template", "Normal.dotm"),
        ("Word Count", "1,245 words"),
        ("Revision Number", "7"),
        ("Last Printed", "2023-04-16T11:45:22Z"),
        ("Security", "Password protected"),
        ("Application Version", "16.0.12345.12345")
    ]
    
    for label, value in metadata:
        text = main_font.render(f"{label}: {value}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 30

def draw_network():
    y_offset = 140
    header = header_font.render("Network Intelligence", True, YELLOW)
    screen.blit(header, (50, y_offset))
    y_offset += 40
    
    network_info = [
        ("IP Range", "192.0.2.0 - 192.0.2.255"),
        ("ASN", "AS12345 (Example Network Solutions)"),
        ("Hosting Provider", "DigitalOcean, LLC"),
        ("Data Center", "NYC1 (New York, United States)"),
        ("Services Detected", "HTTP, HTTPS, SSH, SMTP, FTP"),
        ("SSL Certificate", "Let's Encrypt (Valid until 2023-12-01)"),
        ("Technologies", "Nginx, WordPress, PHP 8.1, jQuery, React"),
        ("Open Ports", "22 (SSH), 80 (HTTP), 443 (HTTPS), 21 (FTP)"),
        ("Server OS", "Ubuntu 20.04.4 LTS"),
        ("Response Time", "142 ms"),
        ("IP Geolocation", "New York, United States"),
        ("Blacklist Status", "Clean (Not blacklisted)")
    ]
    
    for label, value in network_info:
        text = main_font.render(f"{label}: {value}", True, WHITE)
        screen.blit(text, (70, y_offset))
        y_offset += 30

def draw_ui():
    # Draw background
    screen.fill(DARK_BG)
    
    # Draw header
    pygame.draw.rect(screen, LIGHT_BG, (0, 0, WIDTH, 130))
    
    # Draw title
    title = title_font.render("HCO OSINT Investigation Tool", True, WHITE)
    screen.blit(title, (WIDTH // 2 - title.get_width() // 2, 5))
    
    # Draw search box and button
    search_box.draw(screen)
    search_button.draw(screen)
    
    # Draw tabs
    for tab in tabs:
        tab.draw(screen)
    
    # Draw action buttons
    for button in action_buttons:
        button.draw(screen)
    
    # Draw content based on active tab
    if current_tab == "Domain Info":
        draw_domain_info()
    elif current_tab == "Social Media":
        draw_social_media()
    elif current_tab == "People Search":
        draw_people_search()
    elif current_tab == "Image Analysis":
        draw_image_analysis()
    elif current_tab == "Metadata":
        draw_metadata()
    elif current_tab == "Network":
        draw_network()
    
    # Draw footer
    pygame.draw.rect(screen, LIGHT_BG, (0, HEIGHT - 30, WIDTH, 30))
    footer_text = small_font.render("HCO OSINT Tool v2.0 | © 2023 Hackers Colony Official | For educational purposes only", True, WHITE)
    screen.blit(footer_text, (WIDTH // 2 - footer_text.get_width() // 2, HEIGHT - 25))

running = True
while running:
    mouse_pos = pygame.mouse.get_pos()
    
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            running = False
        
        if tool_state == LOCKED:
            subscribe_button.check_hover(mouse_pos)
            if subscribe_button.check_click(mouse_pos, event):
                webbrowser.open(youtube_url)
                tool_state = COUNTDOWN
                start_time = time.time()
        
        elif tool_state == COUNTDOWN:
            if draw_countdown_screen():
                tool_state = SUCCESS
            pygame.display.flip()
            continue
        
        elif tool_state == SUCCESS:
            draw_unlock_screen()
            if event.type == pygame.KEYDOWN:
                tool_state = UNLOCKED
            pygame.display.flip()
            continue
        
        elif tool_state == UNLOCKED:
            # Handle input box events
            result = search_box.handle_event(event)
            if result:
                print(f"Searching for: {result}")
            
            # Handle button hovers
            search_button.check_hover(mouse_pos)
            for button in action_buttons:
                button.check_hover(mouse_pos)
            
            # Handle button clicks
            if search_button.check_click(mouse_pos, event):
                print(f"Initiate search for: {search_box.text}")
            
            for i, button in enumerate(action_buttons):
                if button.check_click(mouse_pos, event):
                    if i == 0:
                        print("Generating report...")
                    elif i == 1:
                        print("Saving results...")
                    elif i == 2:
                        print("Exporting data...")
            
            # Handle tab clicks
            for i, tab in enumerate(tabs):
                if tab.check_click(mouse_pos, event):
                    current_tab = tab.text
                    for other_tab in tabs:
                        if other_tab != tab:
                            other_tab.active = False
    
    # Draw the appropriate screen based on tool state
    if tool_state == LOCKED:
        draw_locked_screen()
    elif tool_state == COUNTDOWN:
        draw_countdown_screen()
    elif tool_state == SUCCESS:
        draw_unlock_screen()
    elif tool_state == UNLOCKED:
        draw_ui()
    
    pygame.display.flip()
    clock.tick(60)

pygame.quit()
sys.exit()
