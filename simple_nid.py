#!/usr/bin/env python3
"""
Network Intrusion Detector - Advanced Network Security Monitoring System
A modern, streamlined interface for network security monitoring and threat analysis
"""

import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
from datetime import datetime
import time
import random
import plotly.express as px
import plotly.graph_objects as go

# Page config with modern styling
st.set_page_config(
    page_title="Network Intrusion Detector",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for modern design
st.markdown("""
<style>
    /* Main theme colors */
    :root {
        --primary-color: #374151;
        --secondary-color: #14b8a6;
        --accent-color: #0d9488;
        --danger-color: #dc2626;
        --warning-color: #d97706;
        --background: #f1f5f9;
        --card-bg: #f8fafc;
        --text-primary: #1e293b;
        --text-secondary: #64748b;
        --border-color: #e2e8f0;
    }
    
    /* Hide default Streamlit elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Disable all tooltips and hover popups */
    [data-testid="tooltip"] {display: none !important;}
    .tooltip {display: none !important;}
    [title] {pointer-events: none !important;}
    [data-tooltip] {pointer-events: none !important;}
    .stTooltip {display: none !important;}
    [aria-describedby] {pointer-events: none !important;}
    
    /* Hide Streamlit help icons and info buttons */
    [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stTooltip"] {display: none !important;}
    .stTooltipIcon {display: none !important;}
    .stInfo {display: none !important;}
    .stHelp {display: none !important;}
    [data-testid="stMetric"] [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stSelectbox"] [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stSlider"] [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stNumberInput"] [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stTextInput"] [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stCheckbox"] [data-testid="stTooltipIcon"] {display: none !important;}
    [data-testid="stButton"] [data-testid="stTooltipIcon"] {display: none !important;}
    
    /* Hide any remaining help/question mark icons */
    svg[data-testid="HelpOutlineIcon"] {display: none !important;}
    svg[data-testid="InfoOutlinedIcon"] {display: none !important;}
    svg[data-testid="HelpIcon"] {display: none !important;}
    svg[data-testid="InfoIcon"] {display: none !important;}
    .help-icon {display: none !important;}
    .info-icon {display: none !important;}
    
    /* Remove all links and clickable help elements */
    a[href*="streamlit.io"] {display: none !important;}
    a[href*="docs.streamlit.io"] {display: none !important;}
    a[href*="github.com"] {display: none !important;}
    .stApp > div > div > div > div > div > div > a {display: none !important;}
    [data-testid="stDecoration"] {display: none !important;}
    [data-testid="stToolbar"] {display: none !important;}
    
    /* Hide Streamlit branding and links */
    .stApp > div > div > div > div > div > div > div > a {display: none !important;}
    .stApp > div > div > div > div > div > div > div > div > a {display: none !important;}
    .stApp a {display: none !important;}
    
    /* Hide any remaining interactive help elements */
    [role="button"][aria-label*="help"] {display: none !important;}
    [role="button"][aria-label*="Help"] {display: none !important;}
    [role="button"][aria-label*="info"] {display: none !important;}
    [role="button"][aria-label*="Info"] {display: none !important;}
    
    /* Hide all SVG icons that might be help related */
    svg {pointer-events: none !important;}
    svg[width="16"] {display: none !important;}
    svg[height="16"] {display: none !important;}
    
    /* Disable hover effects on interactive elements */
    .stButton > button:hover {transform: none !important;}
    .stTabs [data-baseweb="tab"]:hover {background: var(--card-bg) !important; border-color: var(--border-color) !important;}
    .stMetric:hover {transform: none !important;}
    .stSelectbox:hover {transform: none !important;}
    .stSlider:hover {transform: none !important;}
    .stNumberInput:hover {transform: none !important;}
    .stTextInput:hover {transform: none !important;}
    .stCheckbox:hover {transform: none !important;}
    
    /* Main container */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 100%;
    }
    
    /* Custom header */
    .nid-header {
        background: linear-gradient(135deg, #374151 0%, #14b8a6 100%);
        padding: 2rem;
        border-radius: 15px;
        margin-bottom: 2rem;
        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
    }
    
    .nid-title {
        color: white;
        font-size: 2.5rem;
        font-weight: 700;
        margin: 0;
        text-align: center;
    }
    
    .nid-subtitle {
        color: #e5e7eb;
        font-size: 1.1rem;
        text-align: center;
        margin-top: 0.5rem;
    }
    
    /* Status cards */
    .status-card {
        background: var(--card-bg);
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        border-left: 4px solid var(--accent-color);
        margin-bottom: 1rem;
        border: 1px solid var(--border-color);
    }
    
    .status-card.danger {
        border-left-color: var(--danger-color);
    }
    
    .status-card.warning {
        border-left-color: var(--warning-color);
    }
    
    /* Metric cards */
    .metric-card {
        background: var(--card-bg);
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.05);
        text-align: center;
        border: 1px solid var(--border-color);
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: var(--primary-color);
        margin: 0;
    }
    
    .metric-label {
        font-size: 0.9rem;
        color: var(--text-secondary);
        margin: 0.5rem 0 0 0;
    }
    
    /* Threat alerts */
    .threat-alert {
        padding: 1rem;
        border-radius: 8px;
        margin-bottom: 0.5rem;
        border-left: 4px solid;
    }
    
    .threat-alert.high {
        background: #fef2f2;
        border-left-color: var(--danger-color);
        color: #991b1b;
    }
    
    .threat-alert.medium {
        background: #fffbeb;
        border-left-color: var(--warning-color);
        color: #92400e;
    }
    
    .threat-alert.low {
        background: #f0fdfa;
        border-left-color: var(--secondary-color);
        color: #0f766e;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(135deg, var(--secondary-color) 0%, var(--accent-color) 100%);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 0.5rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    
    .stButton > button:hover {
        transform: none;
        box-shadow: none;
    }
    
    /* Sidebar */
    .css-1d391kg {
        background: linear-gradient(180deg, var(--background) 0%, var(--card-bg) 100%);
    }
    
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        padding: 0 0 0 0;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: var(--card-bg);
        border-radius: 8px 8px 0 0;
        border: 1px solid var(--border-color);
        padding: 12px 24px;
        font-size: 16px;
        font-weight: 500;
        min-width: 120px;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .stTabs [data-baseweb="tab"]:hover {
        background: var(--card-bg);
        border-color: var(--border-color);
    }
    
    .stTabs [aria-selected="true"] {
        background: var(--secondary-color);
        color: white;
        border-color: var(--secondary-color);
        box-shadow: 0 2px 4px rgba(20, 184, 166, 0.2);
    }
    
    .stTabs [data-baseweb="tab-panel"] {
        padding: 24px 0 0 0;
    }
</style>
""", unsafe_allow_html=True)

# Load the trained model
@st.cache_resource
def load_model():
    """Load the trained ML model (simulated for demo)"""
    # For demo purposes, we'll simulate a loaded model
    # In a real implementation, you would load an actual trained model here
    return "demo_model"

# Simulate network traffic
def generate_traffic_data():
    """Generate simulated network traffic data"""
    traffic_types = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R', 'DDoS']
    protocols = ['tcp', 'udp', 'icmp']
    
    # Generate random traffic
    traffic = {
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'src_ip': f"192.168.1.{random.randint(1, 254)}",
        'dst_ip': f"192.168.1.{random.randint(1, 254)}",
        'protocol': random.choice(protocols),
        'packet_size': random.randint(64, 1500),
        'traffic_type': random.choice(traffic_types),
        'threat_level': random.choice(['LOW', 'MEDIUM', 'HIGH']) if random.random() < 0.1 else 'NORMAL'
    }
    
    return traffic

# Main app
def main():
    # Custom header
    st.markdown("""
    <div class="nid-header">
        <h1 class="nid-title">Network Intrusion Detector</h1>
        <p class="nid-subtitle">Advanced Network Security Monitoring & Threat Analysis</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Load model (demo mode)
    model = load_model()
    
    # Sidebar - Modern Control Panel
    with st.sidebar:
        st.markdown("### Control Panel")
        
        # System status
        if 'monitoring' not in st.session_state:
            st.session_state.monitoring = False
        
        # Status indicator
        if st.session_state.monitoring:
            st.markdown("""
            <div class="status-card">
                <h4 style="color: #10b981; margin: 0;">SYSTEM ACTIVE</h4>
                <p style="margin: 0.5rem 0 0 0; color: #6b7280;">Real-time monitoring enabled</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="status-card danger">
                <h4 style="color: #ef4444; margin: 0;">SYSTEM STANDBY</h4>
                <p style="margin: 0.5rem 0 0 0; color: #6b7280;">Monitoring disabled</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Control buttons
        if st.button("Start Monitoring" if not st.session_state.monitoring else "Stop Monitoring", 
                    type="primary" if not st.session_state.monitoring else "secondary"):
            st.session_state.monitoring = not st.session_state.monitoring
            st.rerun()
        
        st.markdown("---")
        
        # System info
        st.markdown("### System Info")
        st.metric("Model Accuracy", "99.68%")
        st.metric("Features", "41")
        st.metric("Attack Types", "6")
        
        st.markdown("---")
        
        # Quick actions
        st.markdown("### Quick Actions")
        if st.button("Refresh Data"):
            st.rerun()
        if st.button("Export Report"):
            st.success("Report exported!")
    
    # Main dashboard with tabs
    tab1, tab2 = st.tabs(["Dashboard", "Settings"])
    
    with tab1:
        # Real-time metrics
        if st.session_state.monitoring:
            # Generate traffic data
            traffic_data = []
            for _ in range(random.randint(8, 20)):
                traffic_data.append(generate_traffic_data())
            
            # Top metrics row
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.markdown("""
                <div class="metric-card">
                    <h2 class="metric-value">{}</h2>
                    <p class="metric-label">Total Packets</p>
                </div>
                """.format(len(traffic_data)), unsafe_allow_html=True)
            
            with col2:
                threats = sum(1 for t in traffic_data if t['threat_level'] != 'NORMAL')
                st.markdown("""
                <div class="metric-card">
                    <h2 class="metric-value" style="color: #ef4444;">{}</h2>
                    <p class="metric-label">Active Threats</p>
                </div>
                """.format(threats), unsafe_allow_html=True)
            
            with col3:
                st.markdown("""
                <div class="metric-card">
                    <h2 class="metric-value">{}</h2>
                    <p class="metric-label">Connections</p>
                </div>
                """.format(random.randint(25, 75)), unsafe_allow_html=True)
            
            with col4:
                threat_rate = threats/len(traffic_data)*100 if traffic_data else 0
                st.markdown("""
                <div class="metric-card">
                    <h2 class="metric-value" style="color: #10b981;">{:.1f}%</h2>
                    <p class="metric-label">Threat Rate</p>
                </div>
                """.format(threat_rate), unsafe_allow_html=True)
            
            # Charts section
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                st.markdown("### Protocol Distribution")
                protocols = [t['protocol'] for t in traffic_data]
                protocol_counts = pd.Series(protocols).value_counts()
                
                fig = px.pie(values=protocol_counts.values, names=protocol_counts.index, 
                           color_discrete_sequence=['#14b8a6', '#0d9488', '#d97706'])
                fig.update_layout(showlegend=True, height=300)
                st.plotly_chart(fig, use_container_width=True)
            
            with col_chart2:
                st.markdown("### Traffic Over Time")
                # Simulate time series data
                time_data = pd.DataFrame({
                    'time': pd.date_range(start='2025-09-04 15:00:00', periods=20, freq='1min'),
                    'packets': [random.randint(10, 50) for _ in range(20)]
                })
                
                fig = px.line(time_data, x='time', y='packets', 
                            color_discrete_sequence=['#14b8a6'])
                fig.update_layout(height=300, showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
            
            # Recent activity table
            st.markdown("### Recent Network Activity")
            df = pd.DataFrame(traffic_data)
            st.dataframe(df, use_container_width=True, height=300)
            
            # Auto-refresh
            time.sleep(3)
            st.rerun()
        else:
            st.markdown("""
            <div class="status-card warning">
                <h4 style="color: #f59e0b; margin: 0;">Monitoring Disabled</h4>
                <p style="margin: 0.5rem 0 0 0; color: #6b7280;">Click 'Start Monitoring' to begin real-time analysis</p>
            </div>
            """, unsafe_allow_html=True)
    
    with tab2:
        st.markdown("### System Configuration")
        
        if not st.session_state.monitoring:
            col_config1, col_config2 = st.columns(2)
            
            with col_config1:
                st.markdown("#### Detection Settings")
                
                sensitivity = st.slider("Detection Sensitivity", 0.1, 1.0, 0.7)
                auto_block = st.checkbox("Auto-block High-Risk IPs", value=False)
                alert_email = st.text_input("Alert Email", "admin@company.com")
                
                if st.button("Save Settings"):
                    st.success("Settings saved successfully!")
            
            with col_config2:
                st.markdown("#### Model Performance")
                
                # Performance metrics
                metrics = {
                    "Accuracy": 99.68,
                    "Precision": 98.45,
                    "Recall": 97.23,
                    "F1-Score": 97.84
                }
                
                for metric, value in metrics.items():
                    st.metric(metric, f"{value:.2f}%")
                
                st.markdown("#### Model Actions")
                if st.button("Retrain Model"):
                    st.info("Model retraining initiated...")
                if st.button("Import New Data"):
                    st.info("Data import started...")

if __name__ == "__main__":
    main()
