#!/usr/bin/env python3
"""
Generate a visually stunning PDF report for the Steganography project
"""

from fpdf import FPDF
import textwrap
import math

class VisualPDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
        
    def header(self):
        if self.page_no() > 1:
            # Gradient header bar
            self.draw_gradient_rect(0, 0, 210, 15, (30, 144, 255), (0, 100, 200))
            self.set_font('Arial', 'B', 8)
            self.set_text_color(255, 255, 255)
            self.set_xy(10, 5)
            self.cell(0, 5, 'StealthyData: Advanced Steganography & Forensics Toolkit', align='C')
            self.ln(20)
    
    def footer(self):
        self.set_y(-15)
        # Footer gradient
        self.draw_gradient_rect(0, self.get_y(), 210, 15, (0, 100, 200), (30, 144, 255))
        self.set_font('Arial', 'I', 8)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')
    
    def draw_gradient_rect(self, x, y, w, h, color1, color2):
        """Draw a gradient rectangle"""
        steps = 50
        for i in range(steps):
            ratio = i / steps
            r = int(color1[0] + (color2[0] - color1[0]) * ratio)
            g = int(color1[1] + (color2[1] - color1[1]) * ratio)
            b = int(color1[2] + (color2[2] - color1[2]) * ratio)
            self.set_fill_color(r, g, b)
            self.rect(x, y + i * h / steps, w, h / steps, 'F')
    
    def draw_tech_pattern(self, x, y, w, h):
        """Draw a tech-inspired pattern background"""
        self.set_draw_color(220, 220, 220)
        self.set_line_width(0.2)
        
        # Draw grid pattern
        grid_size = 5
        for i in range(int(w / grid_size) + 1):
            self.line(x + i * grid_size, y, x + i * grid_size, y + h)
        for i in range(int(h / grid_size) + 1):
            self.line(x, y + i * grid_size, x + w, y + i * grid_size)
        
        # Add some tech elements
        self.set_fill_color(240, 248, 255)
        for i in range(0, int(w), 15):
            for j in range(0, int(h), 15):
                if (i + j) % 30 == 0:
                    self.rect(x + i, y + j, 2, 2, 'F')
    
    def create_title_page(self):
        """Create an impressive title page"""
        self.add_page()
        
        # Background pattern
        self.draw_tech_pattern(0, 0, 210, 297)
        
        # Main title background
        self.draw_gradient_rect(10, 40, 190, 40, (0, 123, 255), (0, 86, 179))
        
        # Title
        self.set_font('Arial', 'B', 24)
        self.set_text_color(255, 255, 255)
        self.set_xy(10, 50)
        self.cell(190, 20, 'StealthyData', align='C')
        
        # Subtitle
        self.set_font('Arial', 'B', 14)
        self.set_xy(10, 65)
        self.cell(190, 8, 'Advanced Steganography & Forensics Toolkit', align='C')
        
        # Decorative elements
        self.set_draw_color(0, 123, 255)
        self.set_line_width(2)
        # Draw decorative lines
        self.line(50, 90, 160, 90)
        self.line(70, 95, 140, 95)
        
        # Info box with gradient
        self.draw_gradient_rect(30, 110, 150, 100, (245, 247, 250), (220, 230, 240))
        self.set_draw_color(0, 123, 255)
        self.set_line_width(1)
        self.rect(30, 110, 150, 100)
        
        # Project info
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', 'B', 12)
        self.set_xy(40, 120)
        self.cell(130, 8, 'Advanced Digital Security Solution', align='C')
        
        self.set_font('Arial', '', 10)
        info_items = [
            '• Multiple Steganographic Algorithms',
            '• AES Encryption Integration',
            '• Digital Forensics Capabilities',
            '• Advanced Recovery Mechanisms',
            '• Modern GUI Interface',
            '• Comprehensive Analysis Tools'
        ]
        
        y_pos = 135
        for item in info_items:
            self.set_xy(45, y_pos)
            self.cell(120, 6, item)
            y_pos += 8
        
        # Bottom decorative section
        self.draw_gradient_rect(0, 250, 210, 47, (0, 86, 179), (0, 123, 255))
        self.set_text_color(255, 255, 255)
        self.set_font('Arial', 'I', 10)
        self.set_xy(0, 270)
        self.cell(210, 8, 'Secure • Reliable • Professional', align='C')
    
    def create_section_header(self, title, icon_type="default"):
        """Create a visually appealing section header"""
        # Section background
        self.draw_gradient_rect(10, self.get_y(), 190, 15, (240, 248, 255), (220, 235, 250))
        
        # Icon based on type
        self.set_draw_color(0, 123, 255)
        self.set_fill_color(0, 123, 255)
        icon_x = 15
        icon_y = self.get_y() + 3
        
        if icon_type == "intro":
            # Info icon
            self.circle(icon_x + 4, icon_y + 4, 3, 'D')
            self.set_font('Arial', 'B', 6)
            self.set_text_color(255, 255, 255)
            self.text(icon_x + 2.5, icon_y + 6, 'i')
        elif icon_type == "abstract":
            # Document icon
            self.rect(icon_x + 1, icon_y + 1, 6, 8, 'D')
            self.line(icon_x + 5, icon_y + 1, icon_x + 7, icon_y + 3)
            self.line(icon_x + 5, icon_y + 3, icon_x + 7, icon_y + 3)
        elif icon_type == "tools":
            # Gear icon
            self.circle(icon_x + 4, icon_y + 4, 3, 'D')
            for i in range(8):
                angle = i * math.pi / 4
                x1 = icon_x + 4 + 2 * math.cos(angle)
                y1 = icon_y + 4 + 2 * math.sin(angle)
                x2 = icon_x + 4 + 4 * math.cos(angle)
                y2 = icon_y + 4 + 4 * math.sin(angle)
                self.line(x1, y1, x2, y2)
        elif icon_type == "steps":
            # Process icon
            self.rect(icon_x + 1, icon_y + 2, 3, 3, 'F')
            self.rect(icon_x + 5, icon_y + 2, 3, 3, 'F')
            self.line(icon_x + 4, icon_y + 3.5, icon_x + 5, icon_y + 3.5)
        elif icon_type == "conclusion":
            # Success icon
            self.circle(icon_x + 4, icon_y + 4, 3, 'D')
            self.set_line_width(1)
            self.line(icon_x + 2, icon_y + 4, icon_x + 3.5, icon_y + 5.5)
            self.line(icon_x + 3.5, icon_y + 5.5, icon_x + 6, icon_y + 2.5)
        
        # Title text
        self.set_font('Arial', 'B', 14)
        self.set_text_color(0, 86, 179)
        self.text(30, self.get_y() + 10, title)
        
        self.ln(20)
    
    def create_highlighted_box(self, text, box_type="info"):
        """Create highlighted information boxes"""
        colors = {
            "info": ((240, 248, 255), (0, 123, 255)),
            "warning": ((255, 248, 240), (255, 140, 0)),
            "success": ((240, 255, 240), (40, 167, 69)),
            "tech": ((248, 249, 250), (108, 117, 125))
        }
        
        bg_color, border_color = colors.get(box_type, colors["info"])
        
        # Calculate box height
        lines = textwrap.wrap(text, width=75)
        box_height = len(lines) * 6 + 10
        
        # Draw box
        self.set_fill_color(*bg_color)
        self.set_draw_color(*border_color)
        self.set_line_width(0.5)
        self.rect(15, self.get_y(), 180, box_height, 'DF')
        
        # Add content
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', '', 10)
        y_pos = self.get_y() + 8
        for line in lines:
            self.text(20, y_pos, line)
            y_pos += 6
        
        self.ln(box_height + 5)
    
    def add_bullet_point(self, text, level=0):
        """Add styled bullet points"""
        indent = 20 + level * 10
        self.set_text_color(0, 123, 255)
        self.text(indent, self.get_y() + 4, '•')
        
        self.set_text_color(0, 0, 0)
        self.set_font('Arial', '', 10)
        lines = textwrap.wrap(text, width=70 - level * 5)
        y_pos = self.get_y()
        for i, line in enumerate(lines):
            self.text(indent + 5, y_pos + 4, line)
            if i < len(lines) - 1:
                self.ln(5)
                y_pos = self.get_y()
        self.ln(8)

def create_visual_report():
    # Create PDF object
    pdf = VisualPDF()
    
    # Create title page
    pdf.create_title_page()
    
    # Add new page for content
    pdf.add_page()
    
    # Introduction Section
    pdf.create_section_header("Introduction", "intro")
    
    intro_text = (
        "In the digital age, the need for secure communication and data protection has become paramount. "
        "Steganography, the practice of concealing information within other non-secret data, offers a "
        "sophisticated approach to hiding sensitive information in plain sight."
    )
    pdf.create_highlighted_box(intro_text, "info")
    
    project_text = (
        "The StealthyData project is a comprehensive desktop application designed to provide both "
        "steganographic capabilities for hiding data and advanced forensic tools for data recovery "
        "and analysis. This dual-purpose solution represents the cutting edge of digital security technology."
    )
    
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(0, 0, 0)
    lines = textwrap.wrap(project_text, width=80)
    for line in lines:
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    # Abstract Section
    pdf.create_section_header("Abstract", "abstract")
    
    abstract_text = (
        "StealthyData is a feature-rich desktop application built with Python that combines steganography "
        "techniques with digital forensics capabilities. The application provides a user-friendly graphical "
        "interface for embedding and extracting data from images using multiple steganographic algorithms."
    )
    pdf.create_highlighted_box(abstract_text, "tech")
    
    # Key Features
    pdf.set_font('Arial', 'B', 12)
    pdf.set_text_color(0, 86, 179)
    pdf.cell(0, 8, 'Key Algorithms & Features:', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    
    features = [
        "Least Significant Bit (LSB) - Classic and reliable steganographic technique",
        "Discrete Cosine Transform (DCT) - Frequency domain hiding method",
        "Discrete Wavelet Transform (DWT) - Advanced wavelet-based concealment",
        "Spread Spectrum - Military-grade hiding technique",
        "Adaptive LSB - Intelligent bit modification algorithm"
    ]
    
    for feature in features:
        pdf.add_bullet_point(feature)
    
    # Tools Used Section
    pdf.create_section_header("Tools Used", "tools")
    
    tools_intro = (
        "The StealthyData project leverages cutting-edge Python libraries and frameworks to deliver "
        "professional-grade functionality:"
    )
    pdf.create_highlighted_box(tools_intro, "success")
    
    tools = [
        "Tkinter & tkinterdnd2 - Modern GUI with drag-and-drop functionality",
        "Pillow (PIL) - Advanced image processing and manipulation",
        "Cryptography - Military-grade AES encryption with PBKDF2",
        "NumPy & SciPy - High-performance numerical computations",
        "PyWavelets - Professional wavelet transform implementation"
    ]
    
    for tool in tools:
        pdf.add_bullet_point(tool)
    
    # Add new page for remaining content
    pdf.add_page()
    
    # Steps Section
    pdf.create_section_header("Development Process", "steps")
    
    steps_data = [
        ("UI Design", "Creation of intuitive tabbed interface with specialized widgets"),
        ("Core Algorithms", "Implementation of five advanced steganographic techniques"),
        ("Security Layer", "Integration of AES encryption with secure key derivation"),
        ("Forensics Toolkit", "Development of recovery and analysis mechanisms"),
        ("Analysis Suite", "Advanced detection and verification capabilities"),
        ("Testing & QA", "Comprehensive validation and optimization procedures")
    ]
    
    for i, (step_title, step_desc) in enumerate(steps_data, 1):
        # Step number circle
        pdf.set_fill_color(0, 123, 255)
        pdf.circle(25, pdf.get_y() + 4, 3, 'F')
        pdf.set_font('Arial', 'B', 8)
        pdf.set_text_color(255, 255, 255)
        pdf.text(23, pdf.get_y() + 6, str(i))
        
        # Step content
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(0, 86, 179)
        pdf.text(35, pdf.get_y() + 4, step_title)
        
        pdf.set_font('Arial', '', 10)
        pdf.set_text_color(0, 0, 0)
        pdf.text(35, pdf.get_y() + 10, step_desc)
        pdf.ln(18)
    
    # Conclusion Section
    pdf.create_section_header("Conclusion", "conclusion")
    
    conclusion_highlight = (
        "StealthyData represents a breakthrough in digital security, combining advanced steganographic "
        "techniques with professional forensic analysis capabilities in a single, user-friendly platform."
    )
    pdf.create_highlighted_box(conclusion_highlight, "success")
    
    conclusion_text = (
        "The implementation of multiple steganographic algorithms provides unprecedented flexibility, "
        "while the encryption capabilities ensure maximum security. The forensic toolkit makes this "
        "application invaluable for digital investigators and security professionals. Its modular "
        "design ensures future extensibility, making StealthyData a cornerstone solution for "
        "modern digital security challenges."
    )
    
    try:
        pdf.set_font(pdf.font_family, '', 10)
    except:
        pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(0, 0, 0)
    lines = textwrap.wrap(conclusion_text, width=80)
    for line in lines:
        pdf.cell(0, 6, line, new_x="LMARGIN", new_y="NEXT")
    
    # Final decorative element
    pdf.ln(15)
    pdf.draw_gradient_rect(50, pdf.get_y(), 110, 3, (0, 123, 255), (0, 86, 179))
    
    # Save the PDF
    pdf.output("steganography_visual_report.pdf")
    print("🎉 Visually stunning report generated successfully!")
    print("📄 File saved as: 'steganography_visual_report.pdf'")
    print("✨ Features: Gradients, icons, colored sections, and professional layout!")

if __name__ == "__main__":
    create_visual_report()
