"""Shared UI components for 80 — IAM Audit Tool."""

import streamlit as st

def render_header():
    st.markdown("""
<div style="display:flex;align-items:center;gap:18px;padding:18px 0 14px;border-bottom:1px solid #e8edf2;margin-bottom:24px">
  <div style="width:56px;height:56px;background:#1F3864;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
    <span style="font-size:26px;font-weight:800;color:#ffffff;letter-spacing:-1px;font-family:system-ui,sans-serif">80</span>
  </div>
  <div>
    <div style="font-size:24px;font-weight:700;color:#1F3864;letter-spacing:-0.5px;line-height:1.1;font-family:system-ui,sans-serif">80</div>
    <div style="width:32px;height:2px;background:#1F3864;opacity:0.3;margin:4px 0"></div>
    <div style="font-size:13px;color:#5F6B7A;letter-spacing:0.2px;font-family:system-ui,sans-serif">Identity Access Management Audit Tool</div>
  </div>
</div>
""", unsafe_allow_html=True)


def render_sidebar_brand():
    st.markdown("""
<div style="display:flex;align-items:center;gap:10px;padding:4px 0 12px;border-bottom:1px solid #e8edf2;margin-bottom:8px">
  <div style="width:34px;height:34px;background:#1F3864;border-radius:7px;display:flex;align-items:center;justify-content:center;flex-shrink:0">
    <span style="font-size:15px;font-weight:800;color:#fff;font-family:system-ui,sans-serif">80</span>
  </div>
  <div>
    <div style="font-size:15px;font-weight:700;color:#1F3864;font-family:system-ui,sans-serif;line-height:1.1">80</div>
    <div style="font-size:10px;color:#8a9ab0;font-family:system-ui,sans-serif">IAM Audit Tool</div>
  </div>
</div>
""", unsafe_allow_html=True)

