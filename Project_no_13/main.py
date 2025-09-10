#!/usr/bin/env python3
"""
Steganography Tool - Hide and Extract Data from Images
Supports text messages and file embedding using LSB steganography
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import tkinterdnd2 as tkdnd
from PIL import Image, ImageTk, ImageFilter, ImageEnhance
import os
import base64
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import numpy as np
import scipy.fftpack as fft
import pywt
import hashlib
import time
from collections import defaultdict

class SteganographyTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool - Hide & Extract Data")
        self.root.geometry("800x700")
        self.root.configure(bg='#2c3e50')
        
        # Variables
        self.current_image = None
        self.current_image_path = None
        self.preview_image = None
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main title
        title_frame = tk.Frame(self.root, bg='#2c3e50')
        title_frame.pack(pady=10)
        
        title_label = tk.Label(title_frame, text="🔒 Steganography Tool", 
                              font=('Arial', 20, 'bold'), 
                              fg='#ecf0f1', bg='#2c3e50')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Hide and Extract Secret Data from Images", 
                                 font=('Arial', 10), 
                                 fg='#bdc3c7', bg='#2c3e50')
        subtitle_label.pack()
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Configure notebook style
        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[10, 5])
        
        # Hide tab
        self.hide_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.hide_frame, text='Hide Data')
        
        # Extract tab
        self.extract_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.extract_frame, text='Extract Data')
        
        # Forensics tab
        self.forensics_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(self.forensics_frame, text='Forensics & Recovery')
        
        self.create_hide_widgets()
        self.create_extract_widgets()
        self.create_forensics_widgets()
        
    def create_hide_widgets(self):
        # Image selection frame
        img_frame = tk.LabelFrame(self.hide_frame, text="Select Cover Image", 
                                 font=('Arial', 12, 'bold'), 
                                 fg='#ecf0f1', bg='#34495e')
        img_frame.pack(fill='x', padx=10, pady=5)
        
        # Image preview
        self.img_preview = tk.Label(img_frame, text="Drag & Drop Image Here\nor Click to Browse", 
                                   width=30, height=8, 
                                   bg='#2c3e50', fg='#bdc3c7', 
                                   relief='sunken', bd=2)
        self.img_preview.pack(pady=10)
        self.img_preview.bind('<Button-1>', self.browse_cover_image)
        
        # Drag and drop support
        self.img_preview.drop_target_register(tkdnd.DND_FILES)
        self.img_preview.dnd_bind('<<Drop>>', self.on_image_drop)
        
        browse_btn = tk.Button(img_frame, text="Browse Image", 
                              command=self.browse_cover_image,
                              bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
        browse_btn.pack(pady=5)
        
        # Data input frame
        data_frame = tk.LabelFrame(self.hide_frame, text="Data to Hide", 
                                  font=('Arial', 12, 'bold'), 
                                  fg='#ecf0f1', bg='#34495e')
        data_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Data type selection
        type_frame = tk.Frame(data_frame, bg='#34495e')
        type_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(type_frame, text="Data Type:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.data_type = tk.StringVar(value="text")
        tk.Radiobutton(type_frame, text="Text Message", variable=self.data_type, 
                      value="text", command=self.toggle_data_input,
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(type_frame, text="File", variable=self.data_type, 
                      value="file", command=self.toggle_data_input,
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        
        # Algorithm selection
        algo_frame = tk.Frame(data_frame, bg='#34495e')
        algo_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(algo_frame, text="Algorithm:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.algorithm = tk.StringVar(value="lsb")
        tk.Radiobutton(algo_frame, text="LSB", variable=self.algorithm, 
                      value="lsb",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(algo_frame, text="DCT", variable=self.algorithm, 
                      value="dct",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(algo_frame, text="DWT", variable=self.algorithm, 
                      value="dwt",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(algo_frame, text="Spread Spectrum", variable=self.algorithm, 
                      value="spread",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(algo_frame, text="Adaptive LSB", variable=self.algorithm, 
                      value="adaptive",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        
        # Text input
        self.text_frame = tk.Frame(data_frame, bg='#34495e')
        self.text_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        tk.Label(self.text_frame, text="Secret Message:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.text_input = scrolledtext.ScrolledText(self.text_frame, height=8, 
                                                   bg='#2c3e50', fg='#ecf0f1',
                                                   insertbackground='#ecf0f1')
        self.text_input.pack(fill='both', expand=True, pady=5)
        
        # File input
        self.file_frame = tk.Frame(data_frame, bg='#34495e')
        
        tk.Label(self.file_frame, text="Select File to Hide:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        file_select_frame = tk.Frame(self.file_frame, bg='#34495e')
        file_select_frame.pack(fill='x', pady=5)
        
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(file_select_frame, textvariable=self.file_path_var,
                                  bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.file_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(file_select_frame, text="Browse", command=self.browse_file_to_hide,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Encryption options
        encrypt_frame = tk.Frame(data_frame, bg='#34495e')
        encrypt_frame.pack(fill='x', padx=5, pady=5)
        
        self.use_encryption = tk.BooleanVar()
        encrypt_cb = tk.Checkbutton(encrypt_frame, text="Encrypt data with password", 
                                   variable=self.use_encryption, command=self.toggle_password,
                                   fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50')
        encrypt_cb.pack(anchor='w')
        
        self.password_frame = tk.Frame(encrypt_frame, bg='#34495e')
        
        tk.Label(self.password_frame, text="Password:", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self.password_frame, textvariable=self.password_var,
                                      show='*', bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.password_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # Hide button
        hide_btn = tk.Button(data_frame, text="🔒 Hide Data in Image", 
                            command=self.hide_data,
                            bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
                            pady=10)
        hide_btn.pack(pady=10)
        
        self.toggle_data_input()
        
    def create_extract_widgets(self):
        # Image selection frame
        extract_img_frame = tk.LabelFrame(self.extract_frame, text="Select Stego Image", 
                                         font=('Arial', 12, 'bold'), 
                                         fg='#ecf0f1', bg='#34495e')
        extract_img_frame.pack(fill='x', padx=10, pady=5)
        
        # Image preview for extraction
        self.extract_img_preview = tk.Label(extract_img_frame, 
                                           text="Drag & Drop Stego Image Here\nor Click to Browse", 
                                           width=30, height=6, 
                                           bg='#2c3e50', fg='#bdc3c7', 
                                           relief='sunken', bd=2)
        self.extract_img_preview.pack(pady=10)
        self.extract_img_preview.bind('<Button-1>', self.browse_stego_image)
        
        # Drag and drop support for extraction
        self.extract_img_preview.drop_target_register(tkdnd.DND_FILES)
        self.extract_img_preview.dnd_bind('<<Drop>>', self.on_stego_drop)
        
        browse_stego_btn = tk.Button(extract_img_frame, text="Browse Stego Image", 
                                    command=self.browse_stego_image,
                                    bg='#3498db', fg='white', font=('Arial', 10, 'bold'))
        browse_stego_btn.pack(pady=5)
        
        # Decryption options
        decrypt_frame = tk.LabelFrame(self.extract_frame, text="Decryption Options", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        decrypt_frame.pack(fill='x', padx=10, pady=5)
        
        self.extract_encrypted = tk.BooleanVar()
        decrypt_cb = tk.Checkbutton(decrypt_frame, text="Data is encrypted", 
                                   variable=self.extract_encrypted, command=self.toggle_extract_password,
                                   fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50')
        decrypt_cb.pack(anchor='w', padx=5, pady=5)
        
        # Algorithm selection for extraction
        extract_algo_frame = tk.Frame(decrypt_frame, bg='#34495e')
        extract_algo_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(extract_algo_frame, text="Algorithm:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.extract_algorithm = tk.StringVar(value="lsb")
        tk.Radiobutton(extract_algo_frame, text="LSB", variable=self.extract_algorithm, 
                      value="lsb",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(extract_algo_frame, text="DCT", variable=self.extract_algorithm, 
                      value="dct",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(extract_algo_frame, text="DWT", variable=self.extract_algorithm, 
                      value="dwt",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(extract_algo_frame, text="Spread Spectrum", variable=self.extract_algorithm, 
                      value="spread",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(extract_algo_frame, text="Adaptive LSB", variable=self.extract_algorithm, 
                      value="adaptive",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        
        self.extract_password_frame = tk.Frame(decrypt_frame, bg='#34495e')
        self.extract_password_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(self.extract_password_frame, text="Password:", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.extract_password_var = tk.StringVar()
        self.extract_password_entry = tk.Entry(self.extract_password_frame, 
                                              textvariable=self.extract_password_var,
                                              show='*', bg='#2c3e50', fg='#ecf0f1', 
                                              insertbackground='#ecf0f1')
        self.extract_password_entry.pack(side='left', fill='x', expand=True, padx=5)
        
        # Extract button
        extract_btn = tk.Button(decrypt_frame, text="🔓 Extract Hidden Data", 
                               command=self.extract_data,
                               bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                               pady=10)
        extract_btn.pack(pady=10)
        
        # Results frame
        results_frame = tk.LabelFrame(self.extract_frame, text="Extracted Data", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=10, 
                                                     bg='#2c3e50', fg='#ecf0f1',
                                                     insertbackground='#ecf0f1')
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Save extracted file button
        self.save_file_btn = tk.Button(results_frame, text="💾 Save Extracted File", 
                                      command=self.save_extracted_file,
                                      bg='#9b59b6', fg='white', font=('Arial', 10, 'bold'),
                                      state='disabled')
        self.save_file_btn.pack(pady=5)
        
    def create_forensics_widgets(self):
        # Title for forensics tab
        title_frame = tk.Frame(self.forensics_frame, bg='#34495e')
        title_frame.pack(fill='x', padx=10, pady=5)
        
        title_label = tk.Label(title_frame, text="🔍 Forensics & Recovery Tools", 
                              font=('Arial', 16, 'bold'), 
                              fg='#ecf0f1', bg='#34495e')
        title_label.pack()
        
        subtitle_label = tk.Label(title_frame, text="Advanced tools for data recovery and forensic analysis", 
                                 font=('Arial', 10), 
                                 fg='#bdc3c7', bg='#34495e')
        subtitle_label.pack()
        
        # Notebook for forensics sub-tabs
        forensics_notebook = ttk.Notebook(self.forensics_frame)
        forensics_notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Data Recovery tab
        self.recovery_frame = tk.Frame(forensics_notebook, bg='#34495e')
        forensics_notebook.add(self.recovery_frame, text='Data Recovery')
        
        # Image Repair tab
        self.repair_frame = tk.Frame(forensics_notebook, bg='#34495e')
        forensics_notebook.add(self.repair_frame, text='Image Repair')
        
        # Forensic Analysis tab
        self.analysis_frame = tk.Frame(forensics_notebook, bg='#34495e')
        forensics_notebook.add(self.analysis_frame, text='Forensic Analysis')
        
        # Brute Force Protection tab
        self.protection_frame = tk.Frame(forensics_notebook, bg='#34495e')
        forensics_notebook.add(self.protection_frame, text='Protection')
        
        # Evidence Chain tab
        self.evidence_frame = tk.Frame(forensics_notebook, bg='#34495e')
        forensics_notebook.add(self.evidence_frame, text='Evidence Chain')
        
        self.create_recovery_widgets()
        self.create_repair_widgets()
        self.create_analysis_widgets()
        self.create_protection_widgets()
        self.create_evidence_widgets()
        
    def create_recovery_widgets(self):
        # Data Recovery frame
        recovery_frame = tk.LabelFrame(self.recovery_frame, text="Recover Partially Corrupted Hidden Data", 
                                      font=('Arial', 12, 'bold'), 
                                      fg='#ecf0f1', bg='#34495e')
        recovery_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Image selection for recovery
        img_frame = tk.Frame(recovery_frame, bg='#34495e')
        img_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(img_frame, text="Select Damaged Stego Image:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        select_frame = tk.Frame(img_frame, bg='#34495e')
        select_frame.pack(fill='x', pady=5)
        
        self.recovery_img_path = tk.StringVar()
        self.recovery_img_entry = tk.Entry(select_frame, textvariable=self.recovery_img_path,
                                          bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.recovery_img_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(select_frame, text="Browse", command=self.browse_recovery_image,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Recovery options
        options_frame = tk.Frame(recovery_frame, bg='#34495e')
        options_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(options_frame, text="Recovery Method:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.recovery_method = tk.StringVar(value="error_correction")
        methods_frame = tk.Frame(options_frame, bg='#34495e')
        methods_frame.pack(fill='x', pady=5)
        
        tk.Radiobutton(methods_frame, text="Error Correction", variable=self.recovery_method, 
                      value="error_correction",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(methods_frame, text="Partial Recovery", variable=self.recovery_method, 
                      value="partial",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(methods_frame, text="Brute Force", variable=self.recovery_method, 
                      value="brute_force",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        
        # Password for encrypted data
        password_frame = tk.Frame(recovery_frame, bg='#34495e')
        password_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(password_frame, text="Password (if encrypted):", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.recovery_password = tk.StringVar()
        password_entry = tk.Entry(password_frame, textvariable=self.recovery_password,
                                 show='*', bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        password_entry.pack(fill='x', pady=5)
        
        # Recover button
        recover_btn = tk.Button(recovery_frame, text="🔄 Attempt Data Recovery", 
                               command=self.recover_data,
                               bg='#f39c12', fg='white', font=('Arial', 12, 'bold'),
                               pady=10)
        recover_btn.pack(pady=10)
        
        # Results frame
        results_frame = tk.LabelFrame(recovery_frame, text="Recovery Results", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        results_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.recovery_results = scrolledtext.ScrolledText(results_frame, height=10, 
                                                         bg='#2c3e50', fg='#ecf0f1',
                                                         insertbackground='#ecf0f1')
        self.recovery_results.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Save recovered data button
        self.save_recovered_btn = tk.Button(results_frame, text="💾 Save Recovered Data", 
                                           command=self.save_recovered_data,
                                           bg='#9b59b6', fg='white', font=('Arial', 10, 'bold'),
                                           state='disabled')
        self.save_recovered_btn.pack(pady=5)
        
    def create_repair_widgets(self):
        # Image Repair frame
        repair_frame = tk.LabelFrame(self.repair_frame, text="Repair Damaged Stego Images", 
                                    font=('Arial', 12, 'bold'), 
                                    fg='#ecf0f1', bg='#34495e')
        repair_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Damaged image selection
        damaged_frame = tk.Frame(repair_frame, bg='#34495e')
        damaged_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(damaged_frame, text="Select Damaged Image:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        damaged_select = tk.Frame(damaged_frame, bg='#34495e')
        damaged_select.pack(fill='x', pady=5)
        
        self.damaged_img_path = tk.StringVar()
        self.damaged_img_entry = tk.Entry(damaged_select, textvariable=self.damaged_img_path,
                                         bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.damaged_img_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(damaged_select, text="Browse", command=self.browse_damaged_image,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Reference image selection (for comparison)
        reference_frame = tk.Frame(repair_frame, bg='#34495e')
        reference_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(reference_frame, text="Select Reference Image (Optional):", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        reference_select = tk.Frame(reference_frame, bg='#34495e')
        reference_select.pack(fill='x', pady=5)
        
        self.reference_img_path = tk.StringVar()
        self.reference_img_entry = tk.Entry(reference_select, textvariable=self.reference_img_path,
                                           bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.reference_img_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(reference_select, text="Browse", command=self.browse_reference_image,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Repair options
        repair_options = tk.Frame(repair_frame, bg='#34495e')
        repair_options.pack(fill='x', padx=5, pady=5)
        
        tk.Label(repair_options, text="Repair Method:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.repair_method = tk.StringVar(value="basic")
        methods_frame = tk.Frame(repair_options, bg='#34495e')
        methods_frame.pack(fill='x', pady=5)
        
        tk.Radiobutton(methods_frame, text="Basic Repair", variable=self.repair_method, 
                      value="basic",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(methods_frame, text="Advanced Repair", variable=self.repair_method, 
                      value="advanced",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(methods_frame, text="Noise Reduction", variable=self.repair_method, 
                      value="noise",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        
        # Repair button
        repair_btn = tk.Button(repair_frame, text="🔧 Repair Image", 
                              command=self.repair_image,
                              bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                              pady=10)
        repair_btn.pack(pady=10)
        
        # Results frame
        repair_results = tk.LabelFrame(repair_frame, text="Repair Results", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        repair_results.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.repair_results_text = scrolledtext.ScrolledText(repair_results, height=8, 
                                                           bg='#2c3e50', fg='#ecf0f1',
                                                           insertbackground='#ecf0f1')
        self.repair_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Save repaired image button
        self.save_repaired_btn = tk.Button(repair_results, text="💾 Save Repaired Image", 
                                          command=self.save_repaired_image,
                                          bg='#9b59b6', fg='white', font=('Arial', 10, 'bold'),
                                          state='disabled')
        self.save_repaired_btn.pack(pady=5)
        
    def create_analysis_widgets(self):
        # Forensic Analysis frame
        analysis_frame = tk.LabelFrame(self.analysis_frame, text="Forensic Analysis & Audit Trails", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        analysis_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Image analysis
        image_frame = tk.Frame(analysis_frame, bg='#34495e')
        image_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(image_frame, text="Select Image for Analysis:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        image_select = tk.Frame(image_frame, bg='#34495e')
        image_select.pack(fill='x', pady=5)
        
        self.analysis_img_path = tk.StringVar()
        self.analysis_img_entry = tk.Entry(image_select, textvariable=self.analysis_img_path,
                                          bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.analysis_img_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(image_select, text="Browse", command=self.browse_analysis_image,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Analysis options
        options_frame = tk.Frame(analysis_frame, bg='#34495e')
        options_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(options_frame, text="Analysis Type:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        self.analysis_type = tk.StringVar(value="basic")
        analysis_types = tk.Frame(options_frame, bg='#34495e')
        analysis_types.pack(fill='x', pady=5)
        
        tk.Radiobutton(analysis_types, text="Basic Analysis", variable=self.analysis_type, 
                      value="basic",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(analysis_types, text="Deep Scan", variable=self.analysis_type, 
                      value="deep",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        tk.Radiobutton(analysis_types, text="Statistical Analysis", variable=self.analysis_type, 
                      value="statistical",
                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50').pack(side='left', padx=10)
        
        # Analyze button
        analyze_btn = tk.Button(analysis_frame, text="🔍 Perform Forensic Analysis", 
                               command=self.analyze_image,
                               bg='#3498db', fg='white', font=('Arial', 12, 'bold'),
                               pady=10)
        analyze_btn.pack(pady=10)
        
        # Results frame
        analysis_results = tk.LabelFrame(analysis_frame, text="Analysis Results", 
                                       font=('Arial', 12, 'bold'), 
                                       fg='#ecf0f1', bg='#34495e')
        analysis_results.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.analysis_results_text = scrolledtext.ScrolledText(analysis_results, height=12, 
                                                             bg='#2c3e50', fg='#ecf0f1',
                                                             insertbackground='#ecf0f1')
        self.analysis_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Export analysis button
        export_btn = tk.Button(analysis_results, text="📤 Export Analysis Report", 
                              command=self.export_analysis_report,
                              bg='#e67e22', fg='white', font=('Arial', 10, 'bold'))
        export_btn.pack(pady=5)
        
    def create_protection_widgets(self):
        # Brute Force Protection frame
        protection_frame = tk.LabelFrame(self.protection_frame, text="Brute Force Protection", 
                                       font=('Arial', 12, 'bold'), 
                                       fg='#ecf0f1', bg='#34495e')
        protection_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Protection settings
        settings_frame = tk.Frame(protection_frame, bg='#34495e')
        settings_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(settings_frame, text="Protection Settings:", font=('Arial', 12, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        # Rate limiting
        rate_frame = tk.Frame(settings_frame, bg='#34495e')
        rate_frame.pack(fill='x', pady=5)
        
        tk.Label(rate_frame, text="Max Attempts:", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.max_attempts = tk.StringVar(value="5")
        attempts_entry = tk.Entry(rate_frame, textvariable=self.max_attempts, width=5,
                                 bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        attempts_entry.pack(side='left', padx=5)
        
        tk.Label(rate_frame, text="per", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left', padx=5)
        
        self.time_window = tk.StringVar(value="10")
        time_entry = tk.Entry(rate_frame, textvariable=self.time_window, width=5,
                             bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        time_entry.pack(side='left', padx=5)
        
        tk.Label(rate_frame, text="minutes", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left', padx=5)
        
        # Lockout duration
        lockout_frame = tk.Frame(settings_frame, bg='#34495e')
        lockout_frame.pack(fill='x', pady=5)
        
        tk.Label(lockout_frame, text="Lockout Duration:", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left')
        
        self.lockout_duration = tk.StringVar(value="30")
        lockout_entry = tk.Entry(lockout_frame, textvariable=self.lockout_duration, width=5,
                                bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        lockout_entry.pack(side='left', padx=5)
        
        tk.Label(lockout_frame, text="minutes", font=('Arial', 10),
                fg='#ecf0f1', bg='#34495e').pack(side='left', padx=5)
        
        # Enable protection
        self.protection_enabled = tk.BooleanVar(value=True)
        protection_cb = tk.Checkbutton(settings_frame, text="Enable Brute Force Protection", 
                                      variable=self.protection_enabled,
                                      fg='#ecf0f1', bg='#34495e', selectcolor='#2c3e50',
                                      font=('Arial', 10, 'bold'))
        protection_cb.pack(anchor='w', pady=10)
        
        # Current status
        status_frame = tk.LabelFrame(protection_frame, text="Current Status", 
                                    font=('Arial', 12, 'bold'), 
                                    fg='#ecf0f1', bg='#34495e')
        status_frame.pack(fill='x', padx=5, pady=10)
        
        self.protection_status = tk.Label(status_frame, 
                                         text="🟢 Protection Enabled\nAttempts: 0/5\nTime until reset: 10:00",
                                         font=('Arial', 10), 
                                         fg='#27ae60', bg='#34495e', justify='left')
        self.protection_status.pack(pady=5)
        
        # Reset button
        reset_btn = tk.Button(protection_frame, text="🔄 Reset Protection Counter", 
                             command=self.reset_protection_counter,
                             bg='#e74c3c', fg='white', font=('Arial', 10, 'bold'))
        reset_btn.pack(pady=10)
        
    def create_evidence_widgets(self):
        # Evidence Chain frame
        evidence_frame = tk.LabelFrame(self.evidence_frame, text="Evidence Chain & Data Integrity", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        evidence_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Evidence generation
        gen_frame = tk.Frame(evidence_frame, bg='#34495e')
        gen_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(gen_frame, text="Generate Evidence for File:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        file_select = tk.Frame(gen_frame, bg='#34495e')
        file_select.pack(fill='x', pady=5)
        
        self.evidence_file_path = tk.StringVar()
        self.evidence_file_entry = tk.Entry(file_select, textvariable=self.evidence_file_path,
                                           bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.evidence_file_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(file_select, text="Browse", command=self.browse_evidence_file,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Generate evidence button
        gen_btn = tk.Button(gen_frame, text="📋 Generate Evidence Chain", 
                           command=self.generate_evidence,
                           bg='#9b59b6', fg='white', font=('Arial', 12, 'bold'),
                           pady=10)
        gen_btn.pack(pady=10)
        
        # Evidence display
        evidence_display = tk.LabelFrame(evidence_frame, text="Evidence Chain", 
                                       font=('Arial', 12, 'bold'), 
                                       fg='#ecf0f1', bg='#34495e')
        evidence_display.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.evidence_text = scrolledtext.ScrolledText(evidence_display, height=10, 
                                                     bg='#2c3e50', fg='#ecf0f1',
                                                     insertbackground='#ecf0f1')
        self.evidence_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Verify evidence
        verify_frame = tk.Frame(evidence_frame, bg='#34495e')
        verify_frame.pack(fill='x', padx=5, pady=5)
        
        tk.Label(verify_frame, text="Verify Evidence File:", font=('Arial', 10, 'bold'),
                fg='#ecf0f1', bg='#34495e').pack(anchor='w')
        
        verify_select = tk.Frame(verify_frame, bg='#34495e')
        verify_select.pack(fill='x', pady=5)
        
        self.verify_evidence_path = tk.StringVar()
        self.verify_evidence_entry = tk.Entry(verify_select, textvariable=self.verify_evidence_path,
                                             bg='#2c3e50', fg='#ecf0f1', insertbackground='#ecf0f1')
        self.verify_evidence_entry.pack(side='left', fill='x', expand=True)
        
        tk.Button(verify_select, text="Browse", command=self.browse_verify_evidence,
                 bg='#3498db', fg='white', font=('Arial', 9)).pack(side='right', padx=(5, 0))
        
        # Verify button
        verify_btn = tk.Button(verify_frame, text="✅ Verify Evidence Chain", 
                              command=self.verify_evidence,
                              bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                              pady=10)
        verify_btn.pack(pady=10)
        
        # Verification results
        verify_results = tk.LabelFrame(evidence_frame, text="Verification Results", 
                                     font=('Arial', 12, 'bold'), 
                                     fg='#ecf0f1', bg='#34495e')
        verify_results.pack(fill='x', padx=5, pady=5)
        
        self.verify_results_text = tk.Text(verify_results, height=4, 
                                          bg='#2c3e50', fg='#ecf0f1',
                                          insertbackground='#ecf0f1')
        self.verify_results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
    def toggle_data_input(self):
        if self.data_type.get() == "text":
            self.text_frame.pack(fill='both', expand=True, padx=5, pady=5)
            self.file_frame.pack_forget()
        else:
            self.file_frame.pack(fill='both', expand=True, padx=5, pady=5)
            self.text_frame.pack_forget()
    
    def toggle_password(self):
        if self.use_encryption.get():
            self.password_frame.pack(fill='x', padx=5, pady=5)
        else:
            self.password_frame.pack_forget()
    
    def toggle_extract_password(self):
        if self.extract_encrypted.get():
            self.extract_password_frame.pack(fill='x', padx=5, pady=5)
        else:
            self.extract_password_frame.pack_forget()
    
    # ============= Forensics & Recovery Methods =============
    
    def browse_cover_image(self, event=None):
        file_path = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Image files", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            self.load_cover_image(file_path)
    
    def browse_stego_image(self, event=None):
        file_path = filedialog.askopenfilename(
            title="Select Stego Image",
            filetypes=[("Image files", "*.png *.bmp *.tiff"), ("All files", "*.*")]
        )
        if file_path:
            self.load_stego_image(file_path)
    
    def browse_file_to_hide(self):
        file_path = filedialog.askopenfilename(
            title="Select File to Hide",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def on_image_drop(self, event):
        files = event.data.split()
        if files:
            self.load_cover_image(files[0].strip('{}'))
    
    def on_stego_drop(self, event):
        files = event.data.split()
        if files:
            self.load_stego_image(files[0].strip('{}'))
    
    def load_cover_image(self, file_path):
        try:
            self.current_image = Image.open(file_path)
            self.current_image_path = file_path
            
            # Create preview
            preview = self.current_image.copy()
            preview.thumbnail((200, 150))
            self.preview_image = ImageTk.PhotoImage(preview)
            
            self.img_preview.configure(image=self.preview_image, text="")
            
            # Show image info
            info = f"Image loaded: {os.path.basename(file_path)}\n"
            info += f"Size: {self.current_image.size[0]}x{self.current_image.size[1]}\n"
            info += f"Mode: {self.current_image.mode}"
            
            messagebox.showinfo("Image Loaded", info)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
    
    def load_stego_image(self, file_path):
        try:
            self.stego_image = Image.open(file_path)
            self.stego_image_path = file_path
            
            # Create preview
            preview = self.stego_image.copy()
            preview.thumbnail((200, 120))
            preview_photo = ImageTk.PhotoImage(preview)
            
            self.extract_img_preview.configure(image=preview_photo, text="")
            # Keep a reference to prevent garbage collection
            self.extract_img_preview.image = preview_photo
            
            info = f"Stego image loaded: {os.path.basename(file_path)}"
            messagebox.showinfo("Image Loaded", info)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
    
    def string_to_binary(self, text):
        """Convert string to binary"""
        return ''.join(format(ord(char), '08b') for char in text)
    
    def binary_to_string(self, binary):
        """Convert binary to string"""
        chars = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i+8]
            if len(byte) == 8:
                chars.append(chr(int(byte, 2)))
        return ''.join(chars)
    
    def encrypt_data(self, data, password):
        """Encrypt data using password"""
        password_bytes = password.encode()
        salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
        
        fernet = Fernet(key)
        encrypted = fernet.encrypt(data.encode())
        
        return salt + encrypted
    
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using password"""
        try:
            salt = encrypted_data[:16]
            encrypted = encrypted_data[16:]
            
            password_bytes = password.encode()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
            
            fernet = Fernet(key)
            decrypted = fernet.decrypt(encrypted)
            return decrypted.decode()
        except Exception as e:
            raise Exception("Failed to decrypt data. Check password.")
    
    def embed_data_in_image(self, image, data):
        """Embed binary data in image using selected steganography algorithm"""
        algorithm = self.algorithm.get()
        
        if algorithm == "lsb":
            return self._embed_lsb(image, data)
        elif algorithm == "dct":
            return self._embed_dct(image, data)
        elif algorithm == "dwt":
            return self._embed_dwt(image, data)
        elif algorithm == "spread":
            return self._embed_spread_spectrum(image, data)
        elif algorithm == "adaptive":
            return self._embed_adaptive_lsb(image, data)
        else:
            raise Exception("Unknown algorithm selected")

    def _embed_lsb(self, image, data):
        """Embed binary data in image using LSB steganography"""
        # Convert image to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        image_copy = image.copy()
        width, height = image_copy.size
        
        # Add delimiter to mark end of data
        data += "<<END>>"
        binary_data = self.string_to_binary(data)
        
        data_len = len(binary_data)
        img_capacity = width * height * 3  # 3 color channels
        
        if data_len > img_capacity:
            raise Exception(f"Image too small to hide data. Need {data_len} bits, have {img_capacity}")
        
        data_index = 0
        
        for y in range(height):
            for x in range(width):
                if data_index < data_len:
                    pixel = list(image_copy.getpixel((x, y)))
                    
                    # Modify LSB of each color channel
                    for color in range(3):
                        if data_index < data_len:
                            pixel[color] = pixel[color] & ~1 | int(binary_data[data_index])
                            data_index += 1
                    
                    image_copy.putpixel((x, y), tuple(pixel))
                else:
                    break
            if data_index >= data_len:
                break
        
        return image_copy

    def _embed_dct(self, image, data):
        """Embed binary data in image using DCT steganography"""
        # Convert image to YCbCr for JPEG processing
        if image.mode != 'YCbCr':
            image = image.convert('YCbCr')
        
        # Convert to numpy array
        img_array = np.array(image)
        y_channel = img_array[:, :, 0].astype(np.float32)
        
        # Apply DCT
        dct_coeffs = fft.dctn(y_channel, type=2, norm='ortho')
        
        # Add delimiter to mark end of data
        data += "<<END>>"
        binary_data = self.string_to_binary(data)
        
        # Embed data in DCT coefficients (skip DC coefficient)
        coeff_index = 1
        data_index = 0
        height, width = dct_coeffs.shape
        
        # Flatten coefficients for easier processing
        flat_coeffs = dct_coeffs.flatten()
        
        while data_index < len(binary_data) and coeff_index < len(flat_coeffs):
            # Only modify non-zero coefficients
            if abs(flat_coeffs[coeff_index]) > 0.1:
                # Modify the coefficient to embed data
                coeff = flat_coeffs[coeff_index]
                # Use the sign bit to carry data
                if binary_data[data_index] == '1':
                    flat_coeffs[coeff_index] = abs(coeff) if coeff >= 0 else -abs(coeff)
                else:
                    flat_coeffs[coeff_index] = -abs(coeff) if coeff >= 0 else abs(coeff)
                data_index += 1
            coeff_index += 1
        
        # Reshape back to original shape
        dct_coeffs = flat_coeffs.reshape(dct_coeffs.shape)
        
        # Apply inverse DCT
        y_channel = fft.idctn(dct_coeffs, type=2, norm='ortho')
        
        # Update the Y channel
        img_array[:, :, 0] = np.clip(y_channel, 0, 255).astype(np.uint8)
        
        # Convert back to RGB
        result_image = Image.fromarray(img_array, mode='YCbCr')
        return result_image.convert('RGB')

    def _embed_dwt(self, image, data):
        """Embed binary data in image using DWT steganography"""
        # Convert image to grayscale for DWT
        if image.mode != 'L':
            gray_image = image.convert('L')
        else:
            gray_image = image
        
        # Convert to numpy array
        img_array = np.array(gray_image).astype(np.float32)
        
        # Apply 2D DWT
        coeffs = pywt.dwt2(img_array, 'haar')
        cA, (cH, cV, cD) = coeffs
        
        # Add delimiter to mark end of data
        data += "<<END>>"
        binary_data = self.string_to_binary(data)
        
        # Embed data in approximation coefficients (cA)
        flat_cA = cA.flatten()
        data_index = 0
        
        for i in range(len(flat_cA)):
            if data_index < len(binary_data):
                # Modify LSB of coefficient
                coeff = int(flat_cA[i])
                flat_cA[i] = coeff & ~1 | int(binary_data[data_index])
                data_index += 1
            else:
                break
        
        # Reshape back
        cA = flat_cA.reshape(cA.shape)
        
        # Reconstruct image with modified coefficients
        coeffs_modified = (cA, (cH, cV, cD))
        reconstructed = pywt.idwt2(coeffs_modified, 'haar')
        
        # Convert back to PIL Image
        reconstructed = np.clip(reconstructed, 0, 255).astype(np.uint8)
        result_image = Image.fromarray(reconstructed, mode='L')
        
        # If original was RGB, merge with original color channels
        if image.mode == 'RGB':
            # Create a new RGB image with the stego grayscale as all channels
            rgb_array = np.stack([reconstructed, reconstructed, reconstructed], axis=-1)
            result_image = Image.fromarray(rgb_array, mode='RGB')
        
        return result_image

    def _embed_spread_spectrum(self, image, data):
        """Embed binary data in image using Spread Spectrum steganography"""
        # Convert image to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        image_copy = image.copy()
        pixels = np.array(image_copy)
        height, width, channels = pixels.shape
        
        # Add delimiter to mark end of data
        data += "<<END>>"
        binary_data = self.string_to_binary(data)
        
        # Generate pseudorandom sequence for spreading
        np.random.seed(42)  # Fixed seed for reproducibility
        spread_sequence = np.random.choice([-1, 1], size=len(binary_data))
        
        # Spread data across image
        data_index = 0
        for y in range(height):
            for x in range(width):
                if data_index < len(binary_data):
                    # Modify pixel values based on spread sequence
                    for c in range(channels):
                        if data_index < len(binary_data):
                            # Convert bit to -1 or 1
                            bit_value = 1 if binary_data[data_index] == '1' else -1
                            # Apply spread spectrum technique
                            modification = bit_value * spread_sequence[data_index]
                            
                            # Modify pixel value
                            new_value = int(pixels[y, x, c]) + modification
                            pixels[y, x, c] = np.clip(new_value, 0, 255)
                            
                            data_index += 1
                else:
                    break
            if data_index >= len(binary_data):
                break
        
        result_image = Image.fromarray(pixels, mode='RGB')
        return result_image

    def _embed_adaptive_lsb(self, image, data):
        """Embed binary data in image using Adaptive LSB steganography"""
        # Convert image to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        image_copy = image.copy()
        pixels = np.array(image_copy)
        height, width, channels = pixels.shape
        
        # Add delimiter to mark end of data
        data += "<<END>>"
        binary_data = self.string_to_binary(data)
        
        # Calculate variance for each 4x4 block to determine optimal bits
        block_size = 4
        data_index = 0
        
        for y in range(0, height, block_size):
            for x in range(0, width, block_size):
                if data_index >= len(binary_data):
                    break
                    
                # Get block boundaries
                y_end = min(y + block_size, height)
                x_end = min(x + block_size, width)
                
                # Extract block
                block = pixels[y:y_end, x:x_end]
                
                # Calculate variance of the block
                block_variance = np.var(block)
                
                # Determine number of bits to embed based on variance
                # Higher variance = more bits can be embedded without noticeable change
                if block_variance < 50:  # Low variance - embed 1 bit
                    bits_to_embed = 1
                elif block_variance < 150:  # Medium variance - embed 2 bits
                    bits_to_embed = 2
                else:  # High variance - embed 3 bits
                    bits_to_embed = 3
                
                # Embed bits in the block
                bit_count = 0
                for by in range(y, y_end):
                    for bx in range(x, x_end):
                        if data_index >= len(binary_data) or bit_count >= bits_to_embed:
                            break
                        for c in range(channels):
                            if data_index < len(binary_data) and bit_count < bits_to_embed:
                                # Modify LSB
                                pixels[by, bx, c] = pixels[by, bx, c] & ~1 | int(binary_data[data_index])
                                data_index += 1
                                bit_count += 1
                        if data_index >= len(binary_data) or bit_count >= bits_to_embed:
                            break
                    if data_index >= len(binary_data) or bit_count >= bits_to_embed:
                        break
        
        result_image = Image.fromarray(pixels, mode='RGB')
        return result_image
    
    def extract_data_from_image(self, image):
        """Extract hidden data from image using selected steganography algorithm"""
        algorithm = self.extract_algorithm.get()
        
        if algorithm == "lsb":
            return self._extract_lsb(image)
        elif algorithm == "dct":
            return self._extract_dct(image)
        elif algorithm == "dwt":
            return self._extract_dwt(image)
        elif algorithm == "spread":
            return self._extract_spread_spectrum(image)
        elif algorithm == "adaptive":
            return self._extract_adaptive_lsb(image)
        else:
            raise Exception("Unknown algorithm selected")

    def _extract_lsb(self, image):
        """Extract hidden data from image using LSB steganography"""
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        width, height = image.size
        binary_data = ""
        
        for y in range(height):
            for x in range(width):
                pixel = image.getpixel((x, y))
                
                # Extract LSB from each color channel
                for color in range(3):
                    binary_data += str(pixel[color] & 1)
        
        # Convert binary to string and look for delimiter
        extracted_text = ""
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                extracted_text += char
                
                # Check for end delimiter
                if extracted_text.endswith("<<END>>"):
                    return extracted_text[:-7]  # Remove delimiter
        
        raise Exception("No hidden data found or data is corrupted")

    def _extract_dct(self, image):
        """Extract hidden data from image using DCT steganography"""
        # Convert image to YCbCr for JPEG processing
        if image.mode != 'YCbCr':
            image = image.convert('YCbCr')
        
        # Convert to numpy array
        img_array = np.array(image)
        y_channel = img_array[:, :, 0].astype(np.float32)
        
        # Apply DCT
        dct_coeffs = fft.dctn(y_channel, type=2, norm='ortho')
        
        # Extract data from DCT coefficients
        binary_data = ""
        coeff_index = 1
        height, width = dct_coeffs.shape
        
        # Flatten coefficients for easier processing
        flat_coeffs = dct_coeffs.flatten()
        
        # Extract bits until we find the delimiter
        max_coeffs = min(10000, len(flat_coeffs))  # Limit to prevent infinite loop
        
        while coeff_index < max_coeffs:
            if abs(flat_coeffs[coeff_index]) > 0.1:
                # Extract bit from coefficient sign
                bit = '1' if flat_coeffs[coeff_index] >= 0 else '0'
                binary_data += bit
            coeff_index += 1
            
            # Check if we have enough bits to form a character
            if len(binary_data) % 8 == 0 and len(binary_data) >= 8:
                # Try to decode and check for delimiter
                try:
                    extracted_text = ""
                    for i in range(0, len(binary_data), 8):
                        byte = binary_data[i:i+8]
                        if len(byte) == 8:
                            char = chr(int(byte, 2))
                            extracted_text += char
                    
                    if extracted_text.endswith("<<END>>"):
                        return extracted_text[:-7]  # Remove delimiter
                except:
                    pass
        
        raise Exception("No hidden data found or data is corrupted")

    def _extract_dwt(self, image):
        """Extract hidden data from image using DWT steganography"""
        # Convert image to grayscale for DWT
        if image.mode != 'L':
            gray_image = image.convert('L')
        else:
            gray_image = image
        
        # Convert to numpy array
        img_array = np.array(gray_image).astype(np.float32)
        
        # Apply 2D DWT
        coeffs = pywt.dwt2(img_array, 'haar')
        cA, (cH, cV, cD) = coeffs
        
        # Extract data from approximation coefficients
        flat_cA = cA.flatten()
        binary_data = ""
        
        # Extract bits until we find the delimiter
        max_coeffs = min(10000, len(flat_cA))  # Limit to prevent infinite loop
        
        for i in range(max_coeffs):
            # Extract LSB of coefficient
            bit = str(int(flat_cA[i]) & 1)
            binary_data += bit
            
            # Check if we have enough bits to form a character
            if len(binary_data) % 8 == 0 and len(binary_data) >= 8:
                # Try to decode and check for delimiter
                try:
                    extracted_text = ""
                    for j in range(0, len(binary_data), 8):
                        byte = binary_data[j:j+8]
                        if len(byte) == 8:
                            char = chr(int(byte, 2))
                            extracted_text += char
                    
                    if extracted_text.endswith("<<END>>"):
                        return extracted_text[:-7]  # Remove delimiter
                except:
                    pass
        
        raise Exception("No hidden data found or data is corrupted")

    def _extract_spread_spectrum(self, image):
        """Extract hidden data from image using Spread Spectrum steganography"""
        # Convert image to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        pixels = np.array(image)
        height, width, channels = pixels.shape
        
        # Generate the same pseudorandom sequence used for embedding
        np.random.seed(42)  # Same seed as embedding
        max_bits = height * width * channels
        spread_sequence = np.random.choice([-1, 1], size=max_bits)
        
        # Extract data from image
        binary_data = ""
        data_index = 0
        
        for y in range(height):
            for x in range(width):
                if data_index >= max_bits:
                    break
                # Extract bits from each color channel
                for c in range(channels):
                    if data_index < max_bits:
                        # Extract bit using spread sequence
                        original_value = int(pixels[y, x, c]) - spread_sequence[data_index]
                        bit_value = 1 if original_value > 127 else 0  # Simplified extraction
                        binary_data += str(bit_value)
                        data_index += 1
                if data_index >= max_bits:
                    break
            if data_index >= max_bits:
                break
        
        # Convert binary to string and look for delimiter
        extracted_text = ""
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                try:
                    char = chr(int(byte, 2))
                    extracted_text += char
                    
                    # Check for end delimiter
                    if extracted_text.endswith("<<END>>"):
                        return extracted_text[:-7]  # Remove delimiter
                except:
                    pass
        
        raise Exception("No hidden data found or data is corrupted")

    def _extract_adaptive_lsb(self, image):
        """Extract hidden data from image using Adaptive LSB steganography"""
        # Convert image to RGB if needed
        if image.mode != 'RGB':
            image = image.convert('RGB')
        
        pixels = np.array(image)
        height, width, channels = pixels.shape
        
        # Extract data assuming it was embedded with adaptive LSB
        binary_data = ""
        block_size = 4
        data_index = 0
        
        for y in range(0, height, block_size):
            for x in range(0, width, block_size):
                # Get block boundaries
                y_end = min(y + block_size, height)
                x_end = min(x + block_size, width)
                
                # Extract block
                block = pixels[y:y_end, x:x_end]
                
                # Calculate variance of the block
                block_variance = np.var(block)
                
                # Determine number of bits that were embedded based on variance
                if block_variance < 50:  # Low variance - 1 bit
                    bits_to_extract = 1
                elif block_variance < 150:  # Medium variance - 2 bits
                    bits_to_extract = 2
                else:  # High variance - 3 bits
                    bits_to_extract = 3
                
                # Extract bits from the block
                bit_count = 0
                for by in range(y, y_end):
                    for bx in range(x, x_end):
                        if bit_count >= bits_to_extract:
                            break
                        for c in range(channels):
                            if bit_count < bits_to_extract:
                                # Extract LSB
                                bit = str(pixels[by, bx, c] & 1)
                                binary_data += bit
                                bit_count += 1
                        if bit_count >= bits_to_extract:
                            break
                    if bit_count >= bits_to_extract:
                        break
        
        # Convert binary to string and look for delimiter
        extracted_text = ""
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            if len(byte) == 8:
                try:
                    char = chr(int(byte, 2))
                    extracted_text += char
                    
                    # Check for end delimiter
                    if extracted_text.endswith("<<END>>"):
                        return extracted_text[:-7]  # Remove delimiter
                except:
                    pass
        
        raise Exception("No hidden data found or data is corrupted")
    
    def hide_data(self):
        if not self.current_image:
            messagebox.showerror("Error", "Please select a cover image first")
            return
        
        try:
            # Get data to hide
            if self.data_type.get() == "text":
                data = self.text_input.get("1.0", tk.END).strip()
                if not data:
                    messagebox.showerror("Error", "Please enter text to hide")
                    return
                
                # Create data package
                data_package = {
                    "type": "text",
                    "content": data
                }
            else:
                file_path = self.file_path_var.get()
                if not file_path or not os.path.exists(file_path):
                    messagebox.showerror("Error", "Please select a valid file")
                    return
                
                # Read file and encode as base64
                with open(file_path, "rb") as f:
                    file_data = base64.b64encode(f.read()).decode()
                
                data_package = {
                    "type": "file",
                    "filename": os.path.basename(file_path),
                    "content": file_data
                }
            
            # Convert to JSON string
            data_json = json.dumps(data_package)
            
            # Encrypt if requested
            if self.use_encryption.get():
                password = self.password_var.get()
                if not password:
                    messagebox.showerror("Error", "Please enter a password")
                    return
                
                encrypted_data = self.encrypt_data(data_json, password)
                final_data = base64.b64encode(encrypted_data).decode()
            else:
                final_data = data_json
            
            # Embed data in image
            stego_image = self.embed_data_in_image(self.current_image, final_data)
            
            # Save stego image
            save_path = filedialog.asksaveasfilename(
                title="Save Stego Image",
                defaultextension=".png",
                filetypes=[("PNG files", "*.png"), ("BMP files", "*.bmp"), ("TIFF files", "*.tiff")]
            )
            
            if save_path:
                stego_image.save(save_path)
                messagebox.showinfo("Success", f"Data hidden successfully!\nStego image saved: {save_path}")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data: {str(e)}")
    
    def extract_data(self):
        if not hasattr(self, 'stego_image'):
            messagebox.showerror("Error", "Please select a stego image first")
            return
        
        try:
            # Extract raw data
            extracted_data = self.extract_data_from_image(self.stego_image)
            
            # Decrypt if needed
            if self.extract_encrypted.get():
                password = self.extract_password_var.get()
                if not password:
                    messagebox.showerror("Error", "Please enter the decryption password")
                    return
                
                encrypted_bytes = base64.b64decode(extracted_data.encode())
                extracted_data = self.decrypt_data(encrypted_bytes, password)
            
            # Parse JSON data
            data_package = json.loads(extracted_data)
            
            # Display results based on data type
            self.results_text.delete("1.0", tk.END)
            
            if data_package["type"] == "text":
                self.results_text.insert("1.0", f"Extracted Text Message:\n\n{data_package['content']}")
                self.save_file_btn.configure(state='disabled')
                self.extracted_file_data = None
            
            elif data_package["type"] == "file":
                filename = data_package["filename"]
                file_size = len(base64.b64decode(data_package["content"]))
                
                self.results_text.insert("1.0", f"Extracted File:\n\nFilename: {filename}\nSize: {file_size} bytes\n\nClick 'Save Extracted File' to save the file.")
                
                self.extracted_file_data = {
                    "filename": filename,
                    "content": data_package["content"]
                }
                self.save_file_btn.configure(state='normal')
            
            messagebox.showinfo("Success", "Data extracted successfully!")
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract data: {str(e)}")
    
    def save_extracted_file(self):
        if not self.extracted_file_data:
            return
        
        filename = self.extracted_file_data["filename"]
        save_path = filedialog.asksaveasfilename(
            title="Save Extracted File",
            initialvalue=filename
        )
        
        if save_path:
            try:
                file_data = base64.b64decode(self.extracted_file_data["content"])
                with open(save_path, "wb") as f:
                    f.write(file_data)
                
                messagebox.showinfo("Success", f"File saved successfully!\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    # ============= Forensics & Recovery Methods =============
    
    def browse_recovery_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Damaged Stego Image",
            filetypes=[("Image files", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            self.recovery_img_path.set(file_path)
    
    def browse_damaged_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Damaged Image",
            filetypes=[("Image files", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            self.damaged_img_path.set(file_path)
    
    def browse_reference_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Reference Image",
            filetypes=[("Image files", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            self.reference_img_path.set(file_path)
    
    def browse_analysis_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Image for Analysis",
            filetypes=[("Image files", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            self.analysis_img_path.set(file_path)
    
    def browse_evidence_file(self):
        file_path = filedialog.askopenfilename(
            title="Select File for Evidence Chain",
            filetypes=[("All files", "*.*")]
        )
        if file_path:
            self.evidence_file_path.set(file_path)
    
    def browse_verify_evidence(self):
        file_path = filedialog.askopenfilename(
            title="Select Evidence File",
            filetypes=[("Evidence files", "*.evidence"), ("All files", "*.*")]
        )
        if file_path:
            self.verify_evidence_path.set(file_path)
    
    def recover_data(self):
        image_path = self.recovery_img_path.get()
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid stego image")
            return
        
        try:
            # Load the image
            image = Image.open(image_path)
            
            # Try multiple recovery methods based on selection
            method = self.recovery_method.get()
            password = self.recovery_password.get()
            
            if method == "error_correction":
                recovered_data = self._recover_with_error_correction(image, password)
            elif method == "partial":
                recovered_data = self._recover_partial_data(image, password)
            elif method == "brute_force":
                recovered_data = self._brute_force_recovery(image, password)
            
            # Display results
            self.recovery_results.delete("1.0", tk.END)
            if recovered_data:
                self.recovery_results.insert("1.0", f"Recovered Data:\n\n{recovered_data}")
                self.save_recovered_btn.configure(state='normal')
                self.recovered_data = recovered_data
                messagebox.showinfo("Success", "Data recovery successful!")
            else:
                self.recovery_results.insert("1.0", "Failed to recover data. Try another recovery method.")
                self.save_recovered_btn.configure(state='disabled')
                messagebox.showwarning("Warning", "Data recovery failed or produced no results.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to recover data: {str(e)}")
    
    def _recover_with_error_correction(self, image, password):
        """Recover data using error correction techniques"""
        try:
            # Try to extract data with different algorithms
            algorithms = ["lsb", "dct", "dwt", "spread", "adaptive"]
            for algo in algorithms:
                try:
                    # Temporarily set algorithm
                    original_algo = self.extract_algorithm.get()
                    self.extract_algorithm.set(algo)
                    
                    # Try to extract data
                    extracted_data = self.extract_data_from_image(image)
                    
                    # If encrypted, try to decrypt
                    if password:
                        try:
                            encrypted_bytes = base64.b64decode(extracted_data.encode())
                            extracted_data = self.decrypt_data(encrypted_bytes, password)
                        except:
                            pass  # Not encrypted or wrong password
                    
                    # Restore original algorithm
                    self.extract_algorithm.set(original_algo)
                    
                    # If we got data, return it
                    if extracted_data and not extracted_data.isspace():
                        return extracted_data
                except:
                    continue
            
            return None
        except Exception as e:
            return None
    
    def _recover_partial_data(self, image, password):
        """Recover partial data from corrupted stego image"""
        try:
            # Try to extract as much data as possible
            # This is a simplified implementation
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            width, height = image.size
            binary_data = ""
            
            # Try to extract data with more tolerance for errors
            for y in range(min(height, 100)):  # Limit to first 100 rows for performance
                for x in range(width):
                    try:
                        pixel = image.getpixel((x, y))
                        # Extract LSB from each color channel
                        for color in range(3):
                            binary_data += str(pixel[color] & 1)
                    except:
                        continue
            
            # Try to decode partial data
            extracted_text = ""
            for i in range(0, len(binary_data), 8):
                try:
                    byte = binary_data[i:i+8]
                    if len(byte) == 8:
                        char = chr(int(byte, 2))
                        extracted_text += char
                        
                        # Check for common end patterns
                        if extracted_text.endswith("<<END>>") or len(extracted_text) > 1000:
                            # Try to parse as JSON
                            try:
                                data_package = json.loads(extracted_text.rstrip("<<END>>"))
                                return json.dumps(data_package, indent=2)
                            except:
                                return extracted_text.rstrip("<<END>>")
                except:
                    continue
            
            return extracted_text if extracted_text else None
        except Exception as e:
            return None
    
    def _brute_force_recovery(self, image, password_hint):
        """Attempt brute force recovery with common passwords"""
        common_passwords = [
            "password", "123456", "admin", "user", "steg", "secret",
            "hidden", "data", "image", "forensics", "recover", "access",
            password_hint  # Include the hint if provided
        ]
        
        # Remove duplicates and empty strings
        common_passwords = list(set([p for p in common_passwords if p]))
        
        # Try each password
        for pwd in common_passwords:
            try:
                recovered = self._recover_with_error_correction(image, pwd)
                if recovered:
                    return f"[Recovered with password: {pwd}]\n\n{recovered}"
            except:
                continue
        
        return None
    
    def save_recovered_data(self):
        if not hasattr(self, 'recovered_data') or not self.recovered_data:
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Save Recovered Data",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if save_path:
            try:
                with open(save_path, "w") as f:
                    f.write(self.recovered_data)
                messagebox.showinfo("Success", f"Recovered data saved successfully!\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save recovered data: {str(e)}")
    
    def repair_image(self):
        damaged_path = self.damaged_img_path.get()
        if not damaged_path or not os.path.exists(damaged_path):
            messagebox.showerror("Error", "Please select a valid damaged image")
            return
        
        try:
            # Load the damaged image
            damaged_image = Image.open(damaged_path)
            
            # Apply repair method
            method = self.repair_method.get()
            if method == "basic":
                repaired_image = self._basic_repair(damaged_image)
            elif method == "advanced":
                repaired_image = self._advanced_repair(damaged_image)
            elif method == "noise":
                repaired_image = self._noise_reduction_repair(damaged_image)
            
            # Store the repaired image
            self.repaired_image = repaired_image
            
            # Display results
            self.repair_results_text.delete("1.0", tk.END)
            self.repair_results_text.insert("1.0", f"Image repair completed using {method} method.\n\n"
                                                  f"Original size: {damaged_image.size}\n"
                                                  f"Repaired size: {repaired_image.size if repaired_image else 'N/A'}")
            
            self.save_repaired_btn.configure(state='normal')
            messagebox.showinfo("Success", "Image repair completed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to repair image: {str(e)}")
    
    def _basic_repair(self, image):
        """Basic image repair using PIL's built-in methods"""
        try:
            # Convert to RGB if needed
            if image.mode not in ['RGB', 'RGBA']:
                image = image.convert('RGB')
            
            # Apply basic filters to reduce noise
            from PIL import ImageFilter
            repaired = image.filter(ImageFilter.MedianFilter(size=3))
            return repaired
        except Exception as e:
            return image  # Return original if repair fails
    
    def _advanced_repair(self, image):
        """Advanced image repair using noise reduction and enhancement"""
        try:
            # Convert to RGB if needed
            if image.mode not in ['RGB', 'RGBA']:
                image = image.convert('RGB')
            
            # Apply multiple filters for better repair
            from PIL import ImageFilter, ImageEnhance
            
            # Reduce noise
            repaired = image.filter(ImageFilter.MedianFilter(size=3))
            
            # Enhance sharpness
            enhancer = ImageEnhance.Sharpness(repaired)
            repaired = enhancer.enhance(1.2)
            
            # Enhance contrast
            enhancer = ImageEnhance.Contrast(repaired)
            repaired = enhancer.enhance(1.1)
            
            return repaired
        except Exception as e:
            return image  # Return original if repair fails
    
    def _noise_reduction_repair(self, image):
        """Noise reduction based image repair"""
        try:
            # Convert to RGB if needed
            if image.mode not in ['RGB', 'RGBA']:
                image = image.convert('RGB')
            
            # Convert to numpy array for processing
            img_array = np.array(image)
            
            # Apply Gaussian blur for noise reduction
            from scipy import ndimage
            repaired_array = ndimage.gaussian_filter(img_array, sigma=0.5)
            
            # Convert back to PIL Image
            repaired_image = Image.fromarray(repaired_array.astype('uint8'), 'RGB')
            return repaired_image
        except Exception as e:
            return image  # Return original if repair fails
    
    def save_repaired_image(self):
        if not hasattr(self, 'repaired_image') or not self.repaired_image:
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Save Repaired Image",
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("JPEG files", "*.jpg"), ("BMP files", "*.bmp"), ("All files", "*.*")]
        )
        
        if save_path:
            try:
                self.repaired_image.save(save_path)
                messagebox.showinfo("Success", f"Repaired image saved successfully!\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save repaired image: {str(e)}")
    
    def analyze_image(self):
        image_path = self.analysis_img_path.get()
        if not image_path or not os.path.exists(image_path):
            messagebox.showerror("Error", "Please select a valid image for analysis")
            return
        
        try:
            # Load the image
            image = Image.open(image_path)
            
            # Perform analysis based on selected type
            analysis_type = self.analysis_type.get()
            if analysis_type == "basic":
                analysis_results = self._basic_analysis(image, image_path)
            elif analysis_type == "deep":
                analysis_results = self._deep_scan_analysis(image, image_path)
            elif analysis_type == "statistical":
                analysis_results = self._statistical_analysis(image, image_path)
            
            # Display results
            self.analysis_results_text.delete("1.0", tk.END)
            self.analysis_results_text.insert("1.0", analysis_results)
            messagebox.showinfo("Success", "Forensic analysis completed!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze image: {str(e)}")
    
    def _basic_analysis(self, image, image_path):
        """Perform basic forensic analysis"""
        try:
            # Get basic image information
            info = f"=== Basic Forensic Analysis ===\n\n"
            info += f"File Path: {image_path}\n"
            info += f"File Size: {os.path.getsize(image_path)} bytes\n"
            info += f"Image Format: {image.format}\n"
            info += f"Image Mode: {image.mode}\n"
            info += f"Image Size: {image.size[0]} x {image.size[1]} pixels\n"
            info += f"Total Pixels: {image.size[0] * image.size[1]}\n\n"
            
            # Check for common steganography artifacts
            if image.mode == 'RGB':
                img_array = np.array(image)
                # Calculate basic statistics
                mean_val = np.mean(img_array)
                std_val = np.std(img_array)
                info += f"Mean Pixel Value: {mean_val:.2f}\n"
                info += f"Standard Deviation: {std_val:.2f}\n\n"
                
                # Check for LSB manipulation (common in steganography)
                lsb_analysis = self._analyze_lsb_patterns(img_array)
                info += f"LSB Analysis:\n{lsb_analysis}\n\n"
            
            # Timestamps
            stat = os.stat(image_path)
            info += f"Creation Time: {time.ctime(stat.st_ctime)}\n"
            info += f"Modification Time: {time.ctime(stat.st_mtime)}\n"
            info += f"Access Time: {time.ctime(stat.st_atime)}\n"
            
            return info
        except Exception as e:
            return f"Basic analysis failed: {str(e)}"
    
    def _analyze_lsb_patterns(self, img_array):
        """Analyze LSB patterns for steganography detection"""
        try:
            # Extract LSBs from each color channel
            lsb_r = img_array[:, :, 0] & 1
            lsb_g = img_array[:, :, 1] & 1
            lsb_b = img_array[:, :, 2] & 1
            
            # Calculate entropy of LSBs (randomness test)
            def calculate_entropy(bits):
                hist, _ = np.histogram(bits, bins=2)
                probs = hist / np.sum(hist)
                probs = probs[probs > 0]  # Remove zero probabilities
                entropy = -np.sum(probs * np.log2(probs))
                return entropy
            
            entropy_r = calculate_entropy(lsb_r.flatten())
            entropy_g = calculate_entropy(lsb_g.flatten())
            entropy_b = calculate_entropy(lsb_b.flatten())
            
            # Natural images typically have LSB entropy close to 1.0
            # Values significantly different from 1.0 may indicate steganography
            result = f"  Red Channel LSB Entropy: {entropy_r:.4f}\n"
            result += f"  Green Channel LSB Entropy: {entropy_g:.4f}\n"
            result += f"  Blue Channel LSB Entropy: {entropy_b:.4f}\n"
            
            avg_entropy = (entropy_r + entropy_g + entropy_b) / 3
            if abs(avg_entropy - 1.0) > 0.1:
                result += f"  Note: Unusual LSB entropy detected ({avg_entropy:.4f}). Possible steganography.\n"
            else:
                result += f"  Note: LSB entropy appears normal ({avg_entropy:.4f}).\n"
            
            return result
        except Exception as e:
            return f"  LSB analysis failed: {str(e)}"
    
    def _deep_scan_analysis(self, image, image_path):
        """Perform deep scan forensic analysis"""
        try:
            info = f"=== Deep Scan Forensic Analysis ===\n\n"
            info += self._basic_analysis(image, image_path)
            info += f"\n\n=== Advanced Analysis ===\n\n"
            
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # Chi-square analysis for steganography detection
            chi_square_result = self._chi_square_analysis(img_array)
            info += f"Chi-Square Analysis:\n{chi_square_result}\n\n"
            
            # Pair analysis
            pair_result = self._pair_analysis(img_array)
            info += f"Pair Analysis:\n{pair_result}\n\n"
            
            # RS analysis
            rs_result = self._rs_analysis(img_array)
            info += f"RS Analysis:\n{rs_result}\n"
            
            return info
        except Exception as e:
            return f"Deep scan analysis failed: {str(e)}"
    
    def _chi_square_analysis(self, img_array):
        """Perform chi-square analysis for steganography detection"""
        try:
            result = ""
            for channel in range(3):  # RGB channels
                channel_name = ['Red', 'Green', 'Blue'][channel]
                channel_data = img_array[:, :, channel]
                
                # Calculate histogram for values 0-255
                hist, _ = np.histogram(channel_data, bins=256, range=(0, 256))
                
                # Calculate chi-square statistic
                chi_square = 0
                for i in range(0, 256, 2):
                    if i+1 < 256:
                        even_count = hist[i]
                        odd_count = hist[i+1]
                        if even_count + odd_count > 0:
                            expected = (even_count + odd_count) / 2
                            chi_square += (even_count - expected)**2 / expected if expected > 0 else 0
                            chi_square += (odd_count - expected)**2 / expected if expected > 0 else 0
                
                result += f"  {channel_name} Channel Chi-Square: {chi_square:.2f}\n"
                
                # Interpretation
                if chi_square > 512:  # Threshold for natural images
                    result += f"    Note: High chi-square value may indicate steganography.\n"
                else:
                    result += f"    Note: Chi-square value appears normal.\n"
            
            return result
        except Exception as e:
            return f"  Chi-square analysis failed: {str(e)}"
    
    def _pair_analysis(self, img_array):
        """Perform pair analysis for steganography detection"""
        try:
            result = ""
            for channel in range(3):  # RGB channels
                channel_name = ['Red', 'Green', 'Blue'][channel]
                channel_data = img_array[:, :, channel]
                
                # Calculate pair counts
                pair_counts = np.zeros(256)
                for i in range(channel_data.shape[0]):
                    for j in range(channel_data.shape[1]-1):
                        val1 = channel_data[i, j]
                        val2 = channel_data[i, j+1]
                        if abs(val1 - val2) < 2:  # Similar values
                            pair_counts[val1] += 1
                
                # Calculate pair regularity
                regular_pairs = np.sum(pair_counts > 0)
                total_pairs = 256
                
                regularity = regular_pairs / total_pairs
                result += f"  {channel_name} Channel Pair Regularity: {regularity:.4f}\n"
                
                # Interpretation
                if regularity > 0.9:  # High regularity may indicate steganography
                    result += f"    Note: High pair regularity may indicate steganography.\n"
                else:
                    result += f"    Note: Pair regularity appears normal.\n"
            
            return result
        except Exception as e:
            return f"  Pair analysis failed: {str(e)}"
    
    def _rs_analysis(self, img_array):
        """Perform RS (Regular/Singular) analysis for steganography detection"""
        try:
            result = ""
            for channel in range(3):  # RGB channels
                channel_name = ['Red', 'Green', 'Blue'][channel]
                channel_data = img_array[:, :, channel]
                
                # Simple RS analysis - check for regular patterns
                regular_count = 0
                singular_count = 0
                
                # Sample a portion of the image for performance
                sample_size = min(100, channel_data.shape[0], channel_data.shape[1])
                for i in range(0, sample_size-2):
                    for j in range(0, sample_size-2):
                        # Check 3x3 neighborhood
                        neighborhood = channel_data[i:i+3, j:j+3]
                        if np.std(neighborhood) < 10:  # Low variation = regular
                            regular_count += 1
                        else:  # High variation = singular
                            singular_count += 1
                
                total = regular_count + singular_count
                if total > 0:
                    regular_ratio = regular_count / total
                    result += f"  {channel_name} Channel RS Ratio: {regular_ratio:.4f}\n"
                    
                    # Interpretation
                    if regular_ratio > 0.7:  # High regularity may indicate steganography
                        result += f"    Note: High regularity may indicate steganography.\n"
                    else:
                        result += f"    Note: Regularity appears normal.\n"
                else:
                    result += f"  {channel_name} Channel RS Analysis: Insufficient data\n"
            
            return result
        except Exception as e:
            return f"  RS analysis failed: {str(e)}"
    
    def _statistical_analysis(self, image, image_path):
        """Perform statistical forensic analysis"""
        try:
            info = f"=== Statistical Forensic Analysis ===\n\n"
            info += self._basic_analysis(image, image_path)
            info += f"\n\n=== Statistical Analysis ===\n\n"
            
            # Convert to RGB if needed
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            img_array = np.array(image)
            
            # Calculate various statistical measures
            for channel in range(3):  # RGB channels
                channel_name = ['Red', 'Green', 'Blue'][channel]
                channel_data = img_array[:, :, channel]
                
                info += f"{channel_name} Channel Statistics:\n"
                info += f"  Mean: {np.mean(channel_data):.2f}\n"
                info += f"  Standard Deviation: {np.std(channel_data):.2f}\n"
                info += f"  Variance: {np.var(channel_data):.2f}\n"
                info += f"  Minimum: {np.min(channel_data)}\n"
                info += f"  Maximum: {np.max(channel_data)}\n"
                info += f"  Median: {np.median(channel_data):.2f}\n"
                info += f"  Skewness: {self._calculate_skewness(channel_data):.4f}\n"
                info += f"  Kurtosis: {self._calculate_kurtosis(channel_data):.4f}\n\n"
            
            # Histogram analysis
            info += f"Histogram Analysis:\n"
            info += self._histogram_analysis(img_array)
            
            return info
        except Exception as e:
            return f"Statistical analysis failed: {str(e)}"
    
    def _calculate_skewness(self, data):
        """Calculate skewness of data"""
        try:
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0
            n = len(data.flatten())
            skewness = np.sum(((data - mean) / std) ** 3) / n
            return skewness
        except:
            return 0
    
    def _calculate_kurtosis(self, data):
        """Calculate kurtosis of data"""
        try:
            mean = np.mean(data)
            std = np.std(data)
            if std == 0:
                return 0
            n = len(data.flatten())
            kurtosis = np.sum(((data - mean) / std) ** 4) / n - 3
            return kurtosis
        except:
            return 0
    
    def _histogram_analysis(self, img_array):
        """Perform histogram analysis"""
        try:
            result = ""
            for channel in range(3):  # RGB channels
                channel_name = ['Red', 'Green', 'Blue'][channel]
                channel_data = img_array[:, :, channel]
                
                # Calculate histogram
                hist, _ = np.histogram(channel_data, bins=256, range=(0, 256))
                
                # Check for uniformity
                uniformity = np.sum((hist - np.mean(hist)) ** 2) / len(hist)
                result += f"  {channel_name} Channel Histogram Uniformity: {uniformity:.2f}\n"
                
                # Find peaks
                peaks = np.sum(hist > np.mean(hist) * 2)
                result += f"  {channel_name} Channel Histogram Peaks: {peaks}\n"
                
                # Interpretation
                if uniformity < 1000:  # Low uniformity may indicate steganography
                    result += f"    Note: Low histogram uniformity may indicate steganography.\n"
                else:
                    result += f"    Note: Histogram uniformity appears normal.\n"
            
            return result
        except Exception as e:
            return f"  Histogram analysis failed: {str(e)}\n"
    
    def export_analysis_report(self):
        """Export forensic analysis report to a file"""
        report_content = self.analysis_results_text.get("1.0", tk.END)
        if not report_content.strip():
            messagebox.showwarning("Warning", "No analysis results to export")
            return
        
        save_path = filedialog.asksaveasfilename(
            title="Export Analysis Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("HTML files", "*.html"), ("All files", "*.*")]
        )
        
        if save_path:
            try:
                with open(save_path, "w") as f:
                    f.write(report_content)
                messagebox.showinfo("Success", f"Analysis report exported successfully!\n{save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def reset_protection_counter(self):
        """Reset brute force protection counter"""
        self.protection_status.config(text="🟢 Protection Enabled\nAttempts: 0/5\nTime until reset: 10:00",
                                     fg='#27ae60')
        messagebox.showinfo("Success", "Protection counter reset successfully!")
    
    def generate_evidence(self):
        """Generate evidence chain for a file"""
        file_path = self.evidence_file_path.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file")
            return
        
        try:
            # Generate cryptographic evidence
            evidence_data = self._create_evidence_chain(file_path)
            
            # Display evidence
            self.evidence_text.delete("1.0", tk.END)
            self.evidence_text.insert("1.0", evidence_data)
            
            # Save evidence to file
            save_path = filedialog.asksaveasfilename(
                title="Save Evidence Chain",
                defaultextension=".evidence",
                filetypes=[("Evidence files", "*.evidence"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if save_path:
                try:
                    with open(save_path, "w") as f:
                        f.write(evidence_data)
                    messagebox.showinfo("Success", f"Evidence chain generated and saved!\n{save_path}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save evidence: {str(e)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate evidence: {str(e)}")
    
    def _create_evidence_chain(self, file_path):
        """Create cryptographic evidence chain for a file"""
        try:
            # Get file information
            stat = os.stat(file_path)
            
            # Calculate hashes
            md5_hash = self._calculate_hash(file_path, 'md5')
            sha1_hash = self._calculate_hash(file_path, 'sha1')
            sha256_hash = self._calculate_hash(file_path, 'sha256')
            
            # Generate evidence
            evidence = f"=== Digital Evidence Chain ===\n\n"
            evidence += f"File Path: {file_path}\n"
            evidence += f"File Size: {stat.st_size} bytes\n"
            evidence += f"Creation Time: {time.ctime(stat.st_ctime)}\n"
            evidence += f"Modification Time: {time.ctime(stat.st_mtime)}\n"
            evidence += f"Access Time: {time.ctime(stat.st_atime)}\n\n"
            
            evidence += f"Cryptographic Hashes:\n"
            evidence += f"MD5: {md5_hash}\n"
            evidence += f"SHA1: {sha1_hash}\n"
            evidence += f"SHA256: {sha256_hash}\n\n"
            
            # Generate digital signature (simplified)
            timestamp = int(time.time())
            evidence += f"Timestamp: {timestamp} ({time.ctime(timestamp)})\n"
            evidence += f"Evidence ID: {self._generate_evidence_id(file_path, timestamp)}\n"
            
            return evidence
        except Exception as e:
            return f"Evidence generation failed: {str(e)}"
    
    def _calculate_hash(self, file_path, algorithm):
        """Calculate file hash"""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            return f"Hash calculation failed: {str(e)}"
    
    def _generate_evidence_id(self, file_path, timestamp):
        """Generate unique evidence ID"""
        try:
            # Simple evidence ID generation
            data = f"{file_path}{timestamp}".encode()
            return hashlib.sha256(data).hexdigest()[:16]
        except Exception as e:
            return f"Evidence ID generation failed: {str(e)}"
    
    def verify_evidence(self):
        """Verify evidence chain"""
        evidence_path = self.verify_evidence_path.get()
        if not evidence_path or not os.path.exists(evidence_path):
            messagebox.showerror("Error", "Please select a valid evidence file")
            return
        
        try:
            # Read evidence file
            with open(evidence_path, "r") as f:
                evidence_content = f.read()
            
            # Parse evidence (simplified)
            if "File Path:" in evidence_content:
                # Extract file path from evidence
                lines = evidence_content.split("\n")
                file_line = [line for line in lines if line.startswith("File Path:")]
                if file_line:
                    original_file_path = file_line[0].split(":", 1)[1].strip()
                    
                    # Check if file still exists
                    if os.path.exists(original_file_path):
                        # Recalculate hashes
                        current_md5 = self._calculate_hash(original_file_path, 'md5')
                        current_sha1 = self._calculate_hash(original_file_path, 'sha1')
                        current_sha256 = self._calculate_hash(original_file_path, 'sha256')
                        
                        # Extract original hashes from evidence
                        original_md5 = self._extract_hash_from_evidence(evidence_content, "MD5:")
                        original_sha1 = self._extract_hash_from_evidence(evidence_content, "SHA1:")
                        original_sha256 = self._extract_hash_from_evidence(evidence_content, "SHA256:")
                        
                        # Compare hashes
                        if (current_md5 == original_md5 and 
                            current_sha1 == original_sha1 and 
                            current_sha256 == original_sha256):
                            result = "✅ Evidence verification successful!\n\n"
                            result += "File integrity confirmed.\n"
                            result += "All hashes match the original evidence."
                            self.verify_results_text.config(fg='#27ae60')
                        else:
                            result = "❌ Evidence verification failed!\n\n"
                            result += "File integrity compromised.\n"
                            result += "Hash mismatch detected."
                            self.verify_results_text.config(fg='#e74c3c')
                    else:
                        result = "❌ Evidence verification failed!\n\n"
                        result += "Original file not found.\n"
                        result += "Cannot verify file integrity."
                        self.verify_results_text.config(fg='#e74c3c')
                else:
                    result = "❌ Evidence verification failed!\n\n"
                    result += "Invalid evidence format.\n"
                    result += "File path not found in evidence."
                    self.verify_results_text.config(fg='#e74c3c')
            else:
                result = "❌ Evidence verification failed!\n\n"
                result += "Invalid evidence format.\n"
                result += "Unsupported evidence file."
                self.verify_results_text.config(fg='#e74c3c')
            
            # Display results
            self.verify_results_text.delete("1.0", tk.END)
            self.verify_results_text.insert("1.0", result)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to verify evidence: {str(e)}")
    
    def _extract_hash_from_evidence(self, evidence_content, hash_type):
        """Extract hash value from evidence content"""
        try:
            lines = evidence_content.split("\n")
            for line in lines:
                if line.startswith(hash_type):
                    return line.split(":", 1)[1].strip()
            return ""
        except:
            return ""

def main():
    # Create main window with drag-and-drop support
    root = tkdnd.TkinterDnD.Tk()
    app = SteganographyTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()
