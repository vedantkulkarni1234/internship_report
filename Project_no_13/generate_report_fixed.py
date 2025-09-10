#!/usr/bin/env python3
"""
Generate a PDF report for the Steganography project
"""

from fpdf import FPDF
import textwrap

class PDF(FPDF):
    def header(self):
        if self.page_no() > 1:  # Don't add header to title page
            self.set_font('Helvetica', 'B', 12)
            self.cell(0, 10, 'StealthyData: Advanced Steganography & Forensics Toolkit', border=0, ln=True, align='C')
            self.ln(5)

    def footer(self):
        if self.page_no() > 1:  # Don't add footer to title page
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no() - 1}', align='C')

def create_report():
    # Create PDF object
    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Title Page
    pdf.add_page()
    
    # Title
    pdf.set_font('Helvetica', 'B', 20)
    pdf.cell(0, 20, "StealthyData", ln=True, align='C')
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, "Advanced Steganography & Forensics Toolkit", ln=True, align='C')
    pdf.ln(20)
    
    # Center the following content
    pdf.set_font('Helvetica', '', 12)
    pdf.cell(0, 10, "Project Report", ln=True, align='C')
    pdf.ln(10)
    
    # Date
    from datetime import datetime
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%B %d, %Y')}", ln=True, align='C')
    pdf.ln(30)
    
    # Introduction Page
    pdf.add_page()
    
    # Introduction
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, "Introduction", ln=True)
    pdf.set_font('Helvetica', '', 12)
    
    intro_text = (
        "In the digital age, the need for secure communication and data protection has become paramount. "
        "Steganography, the practice of concealing information within other non-secret data, offers a "
        "sophisticated approach to hiding sensitive information in plain sight. The StealthyData project "
        "is a comprehensive desktop application designed to provide both steganographic capabilities for "
        "hiding data and advanced forensic tools for data recovery and analysis."
    )
    lines = textwrap.wrap(intro_text, width=80)
    for line in lines:
        pdf.cell(0, 8, line, ln=True)
    pdf.ln(5)
    
    # Abstract
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, "Abstract", ln=True)
    pdf.set_font('Helvetica', '', 12)
    
    abstract_text = (
        "StealthyData is a feature-rich desktop application built with Python that combines steganography "
        "techniques with digital forensics capabilities. The application provides a user-friendly graphical "
        "interface for embedding and extracting data from images using multiple steganographic algorithms, "
        "including Least Significant Bit (LSB), Discrete Cosine Transform (DCT), Discrete Wavelet Transform "
        "(DWT), Spread Spectrum, and Adaptive LSB techniques. Additionally, it offers advanced forensic tools "
        "for data recovery, image repair, and steganalysis. The application supports both text and file "
        "embedding, with optional AES encryption for enhanced security. Its forensic suite includes error "
        "correction mechanisms, partial data recovery, brute-force protection, and comprehensive image "
        "analysis tools for detecting hidden data. This dual-purpose design makes it valuable for both "
        "legitimate steganographic applications and digital forensics investigations."
    )
    lines = textwrap.wrap(abstract_text, width=80)
    for line in lines:
        pdf.cell(0, 8, line, ln=True)
    pdf.ln(5)
    
    # Tools Used
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, "Tools Used", ln=True)
    pdf.set_font('Helvetica', '', 12)
    
    tools_text = (
        "The StealthyData project is built using Python and leverages several key libraries and frameworks: "
        "1) Tkinter & tkinterdnd2 for creating the graphical user interface with drag-and-drop functionality, "
        "2) Pillow (PIL) for image processing and manipulation, "
        "3) cryptography for implementing AES encryption with PBKDF2 key derivation, "
        "4) NumPy & SciPy for numerical computations and scientific computing, and "
        "5) PyWavelets for implementing wavelet transforms in steganographic algorithms. "
        "The application uses a modern dark-themed interface that provides an intuitive user experience with "
        "tabbed navigation for different functionalities: Hide Data, Extract Data, and Forensics & Recovery."
    )
    lines = textwrap.wrap(tools_text, width=80)
    for line in lines:
        pdf.cell(0, 8, line, ln=True)
    pdf.ln(5)
    
    # Steps Involved in Building the Project
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, "Steps Involved in Building the Project", ln=True)
    pdf.set_font('Helvetica', '', 12)
    
    steps_text = (
        "The development of StealthyData followed these key steps: "
        "1) UI Design - Creation of a tabbed interface with three main sections (Hide Data, Extract Data, "
        "and Forensics & Recovery) with specialized widgets for each functionality. "
        "2) Core Steganography Implementation - Implementation of five different steganographic algorithms: "
        "LSB (Least Significant Bit), DCT (Discrete Cosine Transform), DWT (Discrete Wavelet Transform), "
        "Spread Spectrum, and Adaptive LSB techniques. "
        "3) Encryption Integration - Implementation of AES encryption using the cryptography library with "
        "PBKDF2 for key derivation, allowing users to secure their hidden data with passwords. "
        "4) Forensics Toolkit Development - Creation of advanced recovery mechanisms including error correction "
        "for corrupted stego-images, partial data recovery techniques, brute-force attack simulation with rate "
        "limiting, and image repair functionality using various filtering methods. "
        "5) Analysis Tools - Implementation of forensic analysis capabilities including basic metadata extraction, "
        "deep scan with statistical tests (Chi-Square, Pair Analysis, RS Analysis), LSB entropy analysis for "
        "steganography detection, and evidence chain generation and verification. "
        "6) Testing and Optimization - Comprehensive testing of all algorithms and features to ensure "
        "reliability and usability."
    )
    lines = textwrap.wrap(steps_text, width=80)
    for line in lines:
        pdf.cell(0, 8, line, ln=True)
    pdf.ln(5)
    
    # Conclusion
    pdf.set_font('Helvetica', 'B', 16)
    pdf.cell(0, 10, "Conclusion", ln=True)
    pdf.set_font('Helvetica', '', 12)
    
    conclusion_text = (
        "The StealthyData project represents a comprehensive solution for both steganographic applications "
        "and digital forensics. Its implementation of multiple steganographic algorithms provides users with "
        "flexibility in choosing the most appropriate technique for their specific needs, while the encryption "
        "capabilities ensure that hidden data remains secure even if the stego-image is discovered. "
        "The inclusion of advanced forensics tools makes this application particularly valuable for digital "
        "investigators who need to detect and recover hidden information. The combination of data recovery "
        "mechanisms, image repair capabilities, and analytical tools provides a complete toolkit for forensic "
        "analysis. The user-friendly interface makes complex steganographic and forensic techniques accessible "
        "to both technical and non-technical users. The modular design allows for easy extension with additional "
        "algorithms or features in the future. Overall, StealthyData demonstrates the practical application of "
        "steganography and digital forensics in a single, cohesive platform. Its dual functionality as both a "
        "steganographic tool and a forensic analysis suite makes it a valuable resource for anyone interested "
        "in information hiding or digital investigation."
    )
    lines = textwrap.wrap(conclusion_text, width=80)
    for line in lines:
        pdf.cell(0, 8, line, ln=True)
    
    # Save the PDF
    pdf.output("steganography_project_report.pdf")
    print("Report generated successfully as 'steganography_project_report.pdf'")

if __name__ == "__main__":
    create_report()