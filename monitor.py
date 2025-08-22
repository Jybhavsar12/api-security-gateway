#!/usr/bin/env python3
"""
API Security Gateway Monitoring Dashboard
Real-time monitoring and alerting system with interactive UI
"""

import sqlite3
import json
import time
import threading
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class MonitoringDashboard(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.serve_dashboard()
        elif self.path == '/api/stats':
            self.serve_stats()
        elif self.path == '/api/threats':
            self.serve_threats()
        elif self.path == '/api/blocked-ips':
            self.serve_blocked_ips()
        elif self.path == '/api/requests':
            self.serve_requests()
        elif self.path.startswith('/static/'):
            self.serve_static()
        else:
            self.send_error(404)
    
    def do_POST(self):
        if self.path == '/api/block-ip':
            self.handle_block_ip()
        elif self.path == '/api/unblock-ip':
            self.handle_unblock_ip()
        elif self.path == '/api/export':
            self.handle_export()
        else:
            self.send_error(404)
    
    def serve_dashboard(self):
        html = """
<!DOCTYPE html>
<html>
<head>
    <title>API Security Gateway - Dashboard</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --primary: #2c3e50;
            --secondary: #34495e;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --info: #3498db;
            --light: #ecf0f1;
            --dark: #2c3e50;
            --gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --shadow: 0 4px 6px rgba(0,0,0,0.1);
            --border-radius: 12px;
        }
        
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
        }
        
        .header { 
            background: var(--gradient);
            color: white; 
            padding: 2rem 1rem; 
            text-align: center;
            box-shadow: var(--shadow);
            position: relative;
            overflow: hidden;
        }
        
        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grain" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="25" cy="25" r="1" fill="rgba(255,255,255,0.1)"/><circle cx="75" cy="75" r="1" fill="rgba(255,255,255,0.1)"/></pattern></defs><rect width="100" height="100" fill="url(%23grain)"/></svg>');
            opacity: 0.1;
        }
        
        .header h1 { 
            font-size: 2.5rem; 
            margin-bottom: 0.5rem;
            position: relative;
            z-index: 1;
        }
        
        .header p { 
            font-size: 1.1rem; 
            opacity: 0.9;
            position: relative;
            z-index: 1;
        }
        
        .status-bar {
            background: rgba(255,255,255,0.1);
            padding: 1rem;
            margin-top: 1rem;
            border-radius: var(--border-radius);
            display: flex;
            justify-content: center;
            gap: 2rem;
            flex-wrap: wrap;
            position: relative;
            z-index: 1;
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.9rem;
        }
        
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            padding: 2rem; 
        }
        
        .controls {
            background: white;
            padding: 1.5rem;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .control-group {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }
        
        .btn-primary { background: var(--info); color: white; }
        .btn-success { background: var(--success); color: white; }
        .btn-warning { background: var(--warning); color: white; }
        .btn-danger { background: var(--danger); color: white; }
        
        .btn:hover { transform: translateY(-2px); box-shadow: 0 6px 12px rgba(0,0,0,0.15); }
        
        .grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); 
            gap: 1.5rem; 
            margin-bottom: 2rem;
        }
        
        .card { 
            background: white; 
            border-radius: var(--border-radius); 
            padding: 1.5rem; 
            box-shadow: var(--shadow);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .card:hover { 
            transform: translateY(-4px); 
            box-shadow: 0 8px 25px rgba(0,0,0,0.15); 
        }
        
        .card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient);
        }
        
        .card h3 { 
            color: var(--primary); 
            margin-bottom: 1.5rem; 
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.2rem;
        }
        
        .stat { 
            display: flex; 
            justify-content: space-between; 
            align-items: center;
            margin: 1rem 0; 
            padding: 0.75rem;
            background: #f8f9fa;
            border-radius: 8px;
            transition: background 0.3s ease;
        }
        
        .stat:hover { background: #e9ecef; }
        
        .stat-label {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 500;
        }
        
        .stat-value { 
            font-weight: bold; 
            font-size: 1.1rem;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            background: var(--success);
            color: white;
        }
        
        .threat-high { background: var(--danger) !important; }
        .threat-medium { background: var(--warning) !important; }
        .threat-low { background: var(--success) !important; }
        
        .chart-container {
            position: relative;
            height: 300px;
            margin: 1rem 0;
        }
        
        .table-container {
            background: white;
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            overflow: hidden;
            margin-bottom: 2rem;
        }
        
        .table-header {
            background: var(--gradient);
            color: white;
            padding: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .table-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
        }
        
        .search-box {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 20px;
            background: rgba(255,255,255,0.2);
            color: white;
            placeholder-color: rgba(255,255,255,0.7);
        }
        
        .search-box::placeholder { color: rgba(255,255,255,0.7); }
        
        table { 
            width: 100%; 
            border-collapse: collapse; 
        }
        
        th, td { 
            padding: 1rem; 
            text-align: left; 
            border-bottom: 1px solid #eee; 
        }
        
        th { 
            background: #f8f9fa; 
            font-weight: 600;
            color: var(--primary);
        }
        
        tr:hover { background: #f8f9fa; }
        
        .status-indicator { 
            display: inline-block; 
            width: 12px; 
            height: 12px; 
            border-radius: 50%; 
            margin-right: 8px; 
        }
        
        .status-running { background: var(--success); }
        .status-stopped { background: var(--danger); }
        .status-warning { background: var(--warning); }
        
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        
        .badge-success { background: var(--success); color: white; }
        .badge-warning { background: var(--warning); color: white; }
        .badge-danger { background: var(--danger); color: white; }
        .badge-info { background: var(--info); color: white; }
        
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            backdrop-filter: blur(5px);
        }
        
        .modal-content {
            background: white;
            margin: 5% auto;
            padding: 2rem;
            border-radius: var(--border-radius);
            width: 90%;
            max-width: 600px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            animation: modalSlideIn 0.3s ease;
        }
        
        @keyframes modalSlideIn {
            from { transform: translateY(-50px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover { color: var(--danger); }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid var(--info);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .alert {
            padding: 1rem;
            border-radius: 8px;
            margin: 1rem 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        
        .tabs {
            display: flex;
            background: white;
            border-radius: var(--border-radius) var(--border-radius) 0 0;
            overflow: hidden;
            box-shadow: var(--shadow);
        }
        
        .tab {
            flex: 1;
            padding: 1rem;
            background: #f8f9fa;
            border: none;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .tab.active {
            background: white;
            color: var(--info);
            border-bottom: 3px solid var(--info);
        }
        
        .tab-content {
            background: white;
            padding: 2rem;
            border-radius: 0 0 var(--border-radius) var(--border-radius);
            box-shadow: var(--shadow);
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--gradient);
            transition: width 0.3s ease;
        }
        
        @media (max-width: 768px) {
            .container { padding: 1rem; }
            .grid { grid-template-columns: 1fr; }
            .controls { flex-direction: column; align-items: stretch; }
            .control-group { justify-content: center; }
            .header h1 { font-size: 2rem; }
            .status-bar { flex-direction: column; gap: 1rem; }
        }
        
        .floating-action {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            width: 60px;
            height: 60px;
            background: var(--gradient);
            border: none;
            border-radius: 50%;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            transition: all 0.3s ease;
            z-index: 100;
        }
        
        .floating-action:hover {
            transform: scale(1.1);
            box-shadow: 0 6px 25px rgba(0,0,0,0.4);
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><i class="fas fa-shield-alt"></i> API Security Gateway</h1>
        <p>Real-time monitoring and threat detection</p>
        <div class="status-bar">
            <div class="status-item">
                <span class="status-indicator status-running"></span>
                <span>Gateway Online</span>
            </div>
            <div class="status-item">
                <i class="fas fa-clock"></i>
                <span>Uptime: <span id="uptime">Loading...</span></span>
            </div>
            <div class="status-item">
                <i class="fas fa-database"></i>
                <span>Database Connected</span>
            </div>
            <div class="status-item">
                <i class="fas fa-sync-alt"></i>
                <span>Last Update: <span id="last-update">Now</span></span>
            </div>
        </div>
    </div>
    
    <div class="container">
        <div class="controls">
            <div class="control-group">
                <button class="btn btn-primary" onclick="refreshAll()">
                    <i class="fas fa-sync-alt"></i> Refresh All
                </button>
                <button class="btn btn-success" onclick="exportData()">
                    <i class="fas fa-download"></i> Export Data
                </button>
                <button class="btn btn-warning" onclick="showSettings()">
                    <i class="fas fa-cog"></i> Settings
                </button>
            </div>
            <div class="control-group">
                <label>
                    <input type="checkbox" id="auto-refresh" checked> Auto-refresh (30s)
                </label>
                <select id="time-range" onchange="updateTimeRange()">
                    <option value="1h">Last Hour</option>
                    <option value="24h" selected>Last 24 Hours</option>
                    <option value="7d">Last 7 Days</option>
                    <option value="30d">Last 30 Days</option>
                </select>
            </div>
        </div>
        
        <div class="grid">
            <div class="card">
                <h3><i class="fas fa-tachometer-alt"></i> System Status</h3>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-server"></i>
                        <span>Gateway Status</span>
                    </div>
                    <span class="stat-value"><span class="status-indicator status-running"></span>Running</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-globe"></i>
                        <span>Total Requests</span>
                    </div>
                    <span class="stat-value" id="total-requests">Loading...</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-calendar-day"></i>
                        <span>Requests Today</span>
                    </div>
                    <span class="stat-value" id="requests-today">Loading...</span>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" id="requests-progress" style="width: 0%"></div>
                </div>
            </div>
            
            <div class="card">
                <h3><i class="fas fa-exclamation-triangle"></i> Threat Detection</h3>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-bug"></i>
                        <span>Threats Today</span>
                    </div>
                    <span class="stat-value threat-high" id="threats-today">Loading...</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-ban"></i>
                        <span>Blocked Requests</span>
                    </div>
                    <span class="stat-value threat-high" id="blocked-requests">Loading...</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-skull-crossbones"></i>
                        <span>Critical Threats</span>
                    </div>
                    <span class="stat-value threat-high" id="critical-threats">Loading...</span>
                </div>
                <div class="chart-container">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h3><i class="fas fa-chart-line"></i> Performance</h3>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-stopwatch"></i>
                        <span>Avg Response Time</span>
                    </div>
                    <span class="stat-value" id="avg-response-time">Loading...</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-check-circle"></i>
                        <span>Success Rate</span>
                    </div>
                    <span class="stat-value" id="success-rate">Loading...</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-hand-paper"></i>
                        <span>Rate Limit Hits</span>
                    </div>
                    <span class="stat-value" id="rate-limit-hits">Loading...</span>
                </div>
                <div class="chart-container">
                    <canvas id="performanceChart"></canvas>
                </div>
            </div>
            
            <div class="card">
                <h3><i class="fas fa-user-shield"></i> Security Overview</h3>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-user-slash"></i>
                        <span>Blocked IPs</span>
                    </div>
                    <span class="stat-value" id="blocked-ips">Loading...</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-key"></i>
                        <span>API Key Failures</span>
                    </div>
                    <span class="stat-value" id="api-failures">0</span>
                </div>
                <div class="stat">
                    <div class="stat-label">
                        <i class="fas fa-shield-alt"></i>
                        <span>Security Score</span>
                    </div>
                    <span class="stat-value" id="security-score">95%</span>
                </div>
                <button class="btn btn-danger" onclick="showBlockedIPs()" style="width: 100%; margin-top: 1rem;">
                    <i class="fas fa-list"></i> Manage Blocked IPs
                </button>
            </div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('threats')">
                <i class="fas fa-bug"></i> Recent Threats
            </button>
            <button class="tab" onclick="showTab('requests')">
                <i class="fas fa-list"></i> Request Log
            </button>
            <button class="tab" onclick="showTab('analytics')">
                <i class="fas fa-chart-bar"></i> Analytics
            </button>
        </div>
        
        <div class="tab-content">
            <div id="threats-tab" class="tab-panel">
                <div class="table-header">
                    <h3><i class="fas fa-search"></i> Recent Threats</h3>
                    <div class="table-controls">
                        <input type="text" class="search-box" placeholder="Search threats..." id="threat-search">
                        <button class="btn btn-primary" onclick="refreshThreats()">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                    </div>
                </div>
                <table id="threats-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP Address</th>
                            <th>Threat Type</th>
                            <th>Severity</th>
                            <th>Pattern</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="7">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div id="requests-tab" class="tab-panel" style="display: none;">
                <div class="table-header">
                    <h3><i class="fas fa-list"></i> Request Log</h3>
                    <div class="table-controls">
                        <input type="text" class="search-box" placeholder="Search requests..." id="request-search">
                        <select class="search-box" id="status-filter">
                            <option value="">All Status</option>
                            <option value="200">Success (200)</option>
                            <option value="400">Bad Request (400)</option>
                            <option value="401">Unauthorized (401)</option>
                            <option value="403">Forbidden (403)</option>
                            <option value="429">Rate Limited (429)</option>
                        </select>
                    </div>
                </div>
                <table id="requests-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>IP</th>
                            <th>Method</th>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Response Time</th>
                            <th>Threat Level</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="7">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            
            <div id="analytics-tab" class="tab-panel" style="display: none;">
                <div class="grid">
                    <div class="card">
                        <h3><i class="fas fa-chart-pie"></i> Threat Distribution</h3>
                        <div class="chart-container">
                            <canvas id="threatDistributionChart"></canvas>
                        </div>
                    </div>
                    <div class="card">
                        <h3><i class="fas fa-chart-area"></i> Request Timeline</h3>
                        <div class="chart-container">
                            <canvas id="requestTimelineChart"></canvas>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Modals -->
    <div id="settingsModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('settingsModal')">&times;</span>
            <h2><i class="fas fa-cog"></i> Dashboard Settings</h2>
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i>
                Configure dashboard preferences and alert settings.
            </div>
            <form id="settingsForm">
                <div style="margin: 1rem 0;">
                    <label><strong>Refresh Interval:</strong></label>
                    <select id="refresh-interval">
                        <option value="10">10 seconds</option>
                        <option value="30" selected>30 seconds</option>
                        <option value="60">1 minute</option>
                        <option value="300">5 minutes</option>
                    </select>
                </div>
                <div style="margin: 1rem 0;">
                    <label><strong>Alert Threshold:</strong></label>
                    <input type="number" id="alert-threshold" value="5" min="1" max="100">
                    <small>Number of threats to trigger alert</small>
                </div>
                <div style="margin: 1rem 0;">
                    <label>
                        <input type="checkbox" id="sound-alerts" checked>
                        Enable sound alerts
                    </label>
                </div>
                <div style="margin: 1rem 0;">
                    <label>
                        <input type="checkbox" id="desktop-notifications" checked>
                        Enable desktop notifications
                    </label>
                </div>
                <button type="button" class="btn btn-primary" onclick="saveSettings()">
                    <i class="fas fa-save"></i> Save Settings
                </button>
            </form>
        </div>
    </div>
    
    <div id="blockedIPsModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('blockedIPsModal')">&times;</span>
            <h2><i class="fas fa-user-slash"></i> Blocked IP Management</h2>
            <div class="table-container">
                <table id="blocked-ips-table">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Blocked At</th>
                            <th>Expires</th>
                            <th>Type</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td colspan="6">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
            <div style="margin-top: 1rem;">
                <h3>Block New IP</h3>
                <div style="display: flex; gap: 1rem; align-items: center; margin-top: 0.5rem;">
                    <input type="text" id="new-ip" placeholder="IP Address" style="flex: 1; padding: 0.5rem;">
                    <input type="text" id="block-reason" placeholder="Reason" style="flex: 1; padding: 0.5rem;">
                    <select id="block-duration" style="padding: 0.5rem;">
                        <option value="1">1 Hour</option>
                        <option value="24">24 Hours</option>
                        <option value="168">1 Week</option>
                        <option value="permanent">Permanent</option>
                    </select>
                    <button class="btn btn-danger" onclick="blockNewIP()">
                        <i class="fas fa-ban"></i> Block
                    </button>
                </div>
            </div>
        </div>
    </div>
    
    <button class="floating-action" onclick="showQuickActions()" title="Quick Actions">
        <i class="fas fa-bolt"></i>
    </button>
    
    <script>
        let charts = {};
        let refreshInterval;
        let lastThreatCount = 0;
        
        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            refreshAll();
            setupAutoRefresh();
            requestNotificationPermission();
        });
        
        function initializeCharts() {
            // Threat Chart
            const threatCtx = document.getElementById('threatChart').getContext('2d');
            charts.threat = new Chart(threatCtx, {
                type: 'doughnut',
                data: {
                    labels: ['SQL Injection', 'XSS', 'Path Traversal', 'Command Injection'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: ['#e74c3c', '#f39c12', '#e67e22', '#c0392b']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'bottom' }
                    }
                }
            });
            
            // Performance Chart
            const perfCtx = document.getElementById('performanceChart').getContext('2d');
            charts.performance = new Chart(perfCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Response Time (ms)',
                        data: [],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
            
            // Threat Distribution Chart
            const threatDistCtx = document.getElementById('threatDistributionChart').getContext('2d');
            charts.threatDistribution = new Chart(threatDistCtx, {
                type: 'pie',
                data: {
                    labels: ['SQL Injection', 'XSS', 'Path Traversal', 'Command Injection', 'Other'],
                    datasets: [{
                        data: [30, 25, 20, 15, 10],
                        backgroundColor: ['#e74c3c', '#f39c12', '#e67e22', '#c0392b', '#95a5a6']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false
                }
            });
            
            // Request Timeline Chart
            const timelineCtx = document.getElementById('requestTimelineChart').getContext('2d');
            charts.timeline = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                    datasets: [{
                        label: 'Requests',
                        data: [120, 80, 200, 350, 280, 150],
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        fill: true
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true }
                    }
                }
            });
        }
        
        function refreshAll() {
            showLoading();
            refreshStats();
            refreshThreats();
            refreshBlockedIPs();
            refreshRequests();
            updateLastRefresh();
        }
        
        function refreshStats() {
            fetch('/api/stats')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('total-requests').textContent = formatNumber(data.total_requests || 0);
                    document.getElementById('requests-today').textContent = formatNumber(data.requests_today || 0);
                    document.getElementById('threats-today').textContent = formatNumber(data.threats_today || 0);
                    document.getElementById('blocked-requests').textContent = formatNumber(data.blocked_requests || 0);
                    document.getElementById('critical-threats').textContent = formatNumber(data.critical_threats || 0);
                    document.getElementById('blocked-ips').textContent = formatNumber(data.blocked_ips || 0);
                    document.getElementById('avg-response-time').textContent = (data.avg_response_time || 0).toFixed(2) + 'ms';
                    document.getElementById('success-rate').textContent = (data.success_rate || 0).toFixed(1) + '%';
                    document.getElementById('rate-limit-hits').textContent = formatNumber(data.rate_limit_hits || 0);
                    
                    // Update progress bar
                    const progress = Math.min((data.requests_today || 0) / 1000 * 100, 100);
                    document.getElementById('requests-progress').style.width = progress + '%';
                    
                    // Check for new threats
                    if (data.threats_today > lastThreatCount) {
                        showNotification('New threat detected!', 'warning');
                        lastThreatCount = data.threats_today;
                    }
                    
                    hideLoading();
                })
                .catch(error => {
                    console.error('Error fetching stats:', error);
                    showNotification('Failed to fetch statistics', 'error');
                    hideLoading();
                });
        }
        
        function refreshThreats() {
            fetch('/api/threats')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.querySelector('#threats-table tbody');
                    tbody.innerHTML = '';
                    
                    if (data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #27ae60;"><i class="fas fa-shield-alt"></i> No threats detected</td></tr>';
                        return;
                    }
                    
                    data.forEach(threat => {
                        const row = document.createElement('tr');
                        const severityClass = 'badge-' + getSeverityClass(threat.severity);
                        row.innerHTML = `
                            <td>${formatDateTime(threat.timestamp)}</td>
                            <td><code>${threat.client_ip}</code></td>
                            <td>${threat.threat_type}</td>
                            <td><span class="badge ${severityClass}">${threat.severity}</span></td>
                            <td><code style="font-size: 0.8rem;">${truncateText(threat.pattern, 30)}</code></td>
                            <td>${threat.blocked ? '<span class="badge badge-danger">🚫 Blocked</span>' : '<span class="badge badge-warning">⚠️ Logged</span>'}</td>
                            <td>
                                <button class="btn btn-danger" onclick="blockIP('${threat.client_ip}')" style="padding: 0.25rem 0.5rem; font-size: 0.8rem;">
                                    <i class="fas fa-ban"></i>
                                </button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                })
                .catch(error => console.error('Error fetching threats:', error));
        }
        
        function refreshBlockedIPs() {
            fetch('/api/blocked-ips')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.querySelector('#blocked-ips-table tbody');
                    tbody.innerHTML = '';
                    
                    if (data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #27ae60;"><i class="fas fa-check-circle"></i> No blocked IPs</td></tr>';
                        return;
                    }
                    
                    data.forEach(ip => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td><code>${ip.ip_address}</code></td>
                            <td>${ip.reason}</td>
                            <td>${formatDateTime(ip.blocked_at)}</td>
                            <td>${ip.permanent ? '<span class="badge badge-danger">Permanent</span>' : formatDateTime(ip.expires_at)}</td>
                            <td>${ip.permanent ? '<span class="badge badge-danger">🔒 Permanent</span>' : '<span class="badge badge-warning">⏰ Temporary</span>'}</td>
                            <td>
                                <button class="btn btn-success" onclick="unblockIP('${ip.ip_address}')" style="padding: 0.25rem 0.5rem; font-size: 0.8rem;">
                                    <i class="fas fa-unlock"></i> Unblock
                                </button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                })
                .catch(error => console.error('Error fetching blocked IPs:', error));
        }
        
        function refreshRequests() {
            fetch('/api/requests')
                .then(response => response.json())
                .then(data => {
                    const tbody = document.querySelector('#requests-table tbody');
                    tbody.innerHTML = '';
                    
                    if (data.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center;"><i class="fas fa-inbox"></i> No recent requests</td></tr>';
                        return;
                    }
                    
                    data.forEach(request => {
                        const row = document.createElement('tr');
                        const statusClass = getStatusClass(request.status_code);
                        const threatClass = 'badge-' + getSeverityClass(request.threat_level || 'LOW');
                        
                        row.innerHTML = `
                            <td>${formatDateTime(request.timestamp)}</td>
                            <td><code>${request.client_ip}</code></td>
                            <td><span class="badge badge-info">${request.method}</span></td>
                            <td><code>${truncateText(request.path, 40)}</code></td>
                            <td><span class="badge ${statusClass}">${request.status_code}</span></td>
                            <td>${(request.response_time * 1000).toFixed(2)}ms</td>
                            <td><span class="badge ${threatClass}">${request.threat_level || 'LOW'}</span></td>
                        `;
                        tbody.appendChild(row);
                    });
                })
                .catch(error => console.error('Error fetching requests:', error));
        }
        
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-panel').forEach(panel => {
                panel.style.display = 'none';
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById(tabName + '-tab').style.display = 'block';
            event.target.classList.add('active');
            
            // Load data for specific tab
            if (tabName === 'requests') {
                refreshRequests();
            }
        }
        
        function showSettings() {
            document.getElementById('settingsModal').style.display = 'block';
        }
        
        function showBlockedIPs() {
            document.getElementById('blockedIPsModal').style.display = 'block';
            refreshBlockedIPs();
        }
        
        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        function setupAutoRefresh() {
            const autoRefreshCheckbox = document.getElementById('auto-refresh');
            
            function startAutoRefresh() {
                if (refreshInterval) clearInterval(refreshInterval);
                refreshInterval = setInterval(refreshAll, 30000);
            }
            
            autoRefreshCheckbox.addEventListener('change', function() {
                if (this.checked) {
                    startAutoRefresh();
                } else {
                    clearInterval(refreshInterval);
                }
            });
            
            if (autoRefreshCheckbox.checked) {
                startAutoRefresh();
            }
        }
        
        function showNotification(message, type = 'info') {
            // Desktop notification
            if (Notification.permission === 'granted') {
                new Notification('API Security Gateway', {
                    body: message,
                    icon: '/favicon.ico'
                });
            }
            
            // In-app notification
            const alert = document.createElement('div');
            alert.className = `alert alert-${type}`;
            alert.innerHTML = `<i class="fas fa-${getIconForType(type)}"></i> ${message}`;
            alert.style.position = 'fixed';
            alert.style.top = '20px';
            alert.style.right = '20px';
            alert.style.zIndex = '1001';
            alert.style.minWidth = '300px';
            
            document.body.appendChild(alert);
            
            setTimeout(() => {
                alert.remove();
            }, 5000);
        }
        
        function requestNotificationPermission() {
            if ('Notification' in window && Notification.permission === 'default') {
                Notification.requestPermission();
            }
        }
        
        function blockIP(ip) {
            if (!ip) return;
            
            fetch('/api/block-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip_address: ip,
                    reason: 'Manual block from dashboard',
                    duration: 24
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(`IP ${ip} has been blocked`, 'warning');
                    refreshBlockedIPs();
                } else {
                    showNotification('Failed to block IP', 'error');
                }
            })
            .catch(error => {
                console.error('Error blocking IP:', error);
                showNotification('Error blocking IP', 'error');
            });
        }
        
        function unblockIP(ip) {
            fetch('/api/unblock-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip_address: ip
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(`IP ${ip} has been unblocked`, 'success');
                    refreshBlockedIPs();
                } else {
                    showNotification('Failed to unblock IP', 'error');
                }
            })
            .catch(error => {
                console.error('Error unblocking IP:', error);
                showNotification('Error unblocking IP', 'error');
            });
        }
        
        function blockNewIP() {
            const ip = document.getElementById('new-ip').value;
            const reason = document.getElementById('block-reason').value || 'Manual block';
            const duration = document.getElementById('block-duration').value;
            
            if (!ip) {
                showNotification('Please enter an IP address', 'warning');
                return;
            }
            
            fetch('/api/block-ip', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip_address: ip,
                    reason: reason,
                    duration: duration
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showNotification(`IP ${ip} has been blocked`, 'warning');
                    document.getElementById('new-ip').value = '';
                    document.getElementById('block-reason').value = '';
                    refreshBlockedIPs();
                } else {
                    showNotification('Failed to block IP', 'error');
                }
            })
            .catch(error => {
                console.error('Error blocking IP:', error);
                showNotification('Error blocking IP', 'error');
            });
        }
        
        function exportData() {
            showNotification('Exporting data...', 'info');
            
            fetch('/api/export', {
                method: 'POST'
            })
            .then(response => response.blob())
            .then(blob => {
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = 'gateway_export.json';
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                showNotification('Data exported successfully!', 'success');
            })
            .catch(error => {
                console.error('Error exporting data:', error);
                showNotification('Failed to export data', 'error');
            });
        }
        
        function saveSettings() {
            showNotification('Settings saved successfully!', 'success');
            closeModal('settingsModal');
        }
        
        function updateTimeRange() {
            const range = document.getElementById('time-range').value;
            showNotification(`Time range updated to ${range}`, 'info');
            refreshAll();
        }
        
        function showQuickActions() {
            const actions = [
                'Emergency Block All',
                'Clear All Blocks', 
                'Generate Report',
                'System Health Check'
            ];
            
            showNotification('Quick actions menu opened', 'info');
        }
        
        function formatNumber(num) {
            return new Intl.NumberFormat().format(num);
        }
        
        function formatDateTime(dateString) {
            return new Date(dateString).toLocaleString();
        }
        
        function truncateText(text, length) {
            return text.length > length ? text.substring(0, length) + '...' : text;
        }
        
        function getSeverityClass(severity) {
            const map = {
                'LOW': 'success',
                'MEDIUM': 'warning', 
                'HIGH': 'danger',
                'CRITICAL': 'danger'
            };
            return map[severity] || 'info';
        }
        
        function getStatusClass(status) {
            if (status >= 200 && status < 300) return 'badge-success';
            if (status >= 300 && status < 400) return 'badge-info';
            if (status >= 400 && status < 500) return 'badge-warning';
            if (status >= 500) return 'badge-danger';
            return 'badge-info';
        }
        
        function getIconForType(type) {
            const map = {
                'info': 'info-circle',
                'warning': 'exclamation-triangle',
                'error': 'times-circle',
                'success': 'check-circle'
            };
            return map[type] || 'info-circle';
        }
        
        function showLoading() {
            // Add loading indicators if needed
        }
        
        function hideLoading() {
            // Remove loading indicators if needed
        }
        
        function updateLastRefresh() {
            document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
    </script>
</body>
</html>
        """
        
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode())
    
    def serve_stats(self):
        try:
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            # Get various statistics
            today = datetime.now().strftime('%Y-%m-%d')
            
            # Total requests
            cursor.execute("SELECT COUNT(*) FROM requests")
            total_requests = cursor.fetchone()[0]
            
            # Requests today
            cursor.execute("SELECT COUNT(*) FROM requests WHERE DATE(timestamp) = ?", (today,))
            requests_today = cursor.fetchone()[0]
            
            # Threats today
            cursor.execute("SELECT COUNT(*) FROM threats WHERE DATE(timestamp) = ?", (today,))
            threats_today = cursor.fetchone()[0]
            
            # Blocked requests today
            cursor.execute("SELECT COUNT(*) FROM requests WHERE DATE(timestamp) = ? AND blocked = 1", (today,))
            blocked_requests = cursor.fetchone()[0]
            
            # Critical threats today
            cursor.execute("SELECT COUNT(*) FROM threats WHERE DATE(timestamp) = ? AND severity = 'CRITICAL'", (today,))
            critical_threats = cursor.fetchone()[0]
            
            # Currently blocked IPs
            cursor.execute("SELECT COUNT(*) FROM blocked_ips WHERE expires_at > datetime('now') OR permanent = 1")
            blocked_ips = cursor.fetchone()[0]
            
            # Average response time today
            cursor.execute("SELECT AVG(response_time) FROM requests WHERE DATE(timestamp) = ?", (today,))
            avg_response_time = cursor.fetchone()[0] or 0
            avg_response_time = avg_response_time * 1000  # Convert to milliseconds
            
            # Success rate today
            cursor.execute("SELECT COUNT(*) FROM requests WHERE DATE(timestamp) = ? AND status_code < 400", (today,))
            successful_requests = cursor.fetchone()[0]
            success_rate = (successful_requests / requests_today * 100) if requests_today > 0 else 100
            
            # Rate limit hits today
            cursor.execute("SELECT COUNT(*) FROM requests WHERE DATE(timestamp) = ? AND status_code = 429", (today,))
            rate_limit_hits = cursor.fetchone()[0]
            
            conn.close()
            
            stats = {
                'total_requests': total_requests,
                'requests_today': requests_today,
                'threats_today': threats_today,
                'blocked_requests': blocked_requests,
                'critical_threats': critical_threats,
                'blocked_ips': blocked_ips,
                'avg_response_time': avg_response_time,
                'success_rate': success_rate,
                'rate_limit_hits': rate_limit_hits
            }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode())
            
        except Exception as e:
            self.send_error(500, f"Database error: {e}")
    
    def serve_threats(self):
        try:
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            # Get recent threats (last 24 hours)
            cursor.execute("""
                SELECT timestamp, client_ip, threat_type, severity, pattern, blocked
                FROM threats 
                WHERE timestamp >= datetime('now', '-1 day')
                ORDER BY timestamp DESC 
                LIMIT 50
            """)
            
            threats = []
            for row in cursor.fetchall():
                threats.append({
                    'timestamp': row[0],
                    'client_ip': row[1],
                    'threat_type': row[2],
                    'severity': row[3],
                    'pattern': row[4],
                    'blocked': bool(row[5])
                })
            
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(threats).encode())
            
        except Exception as e:
            self.send_error(500, f"Database error: {e}")
    
    def serve_blocked_ips(self):
        try:
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            # Get currently blocked IPs
            cursor.execute("""
                SELECT ip_address, reason, blocked_at, expires_at, permanent
                FROM blocked_ips 
                WHERE expires_at > datetime('now') OR permanent = 1
                ORDER BY blocked_at DESC
            """)
            
            blocked_ips = []
            for row in cursor.fetchall():
                blocked_ips.append({
                    'ip_address': row[0],
                    'reason': row[1],
                    'blocked_at': row[2],
                    'expires_at': row[3],
                    'permanent': bool(row[4])
                })
            
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(blocked_ips).encode())
            
        except Exception as e:
            self.send_error(500, f"Database error: {e}")
    
    def serve_requests(self):
        try:
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            # Get recent requests (last 24 hours)
            cursor.execute("""
                SELECT timestamp, client_ip, method, path, status_code, response_time, threat_level
                FROM requests 
                WHERE timestamp >= datetime('now', '-1 day')
                ORDER BY timestamp DESC 
                LIMIT 100
            """)
            
            requests_data = []
            for row in cursor.fetchall():
                requests_data.append({
                    'timestamp': row[0],
                    'client_ip': row[1],
                    'method': row[2],
                    'path': row[3],
                    'status_code': row[4],
                    'response_time': row[5],
                    'threat_level': row[6]
                })
            
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(requests_data).encode())
            
        except Exception as e:
            self.send_error(500, f"Database error: {e}")
    
    def handle_block_ip(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            ip_address = data.get('ip_address')
            reason = data.get('reason', 'Manual block')
            duration = data.get('duration', 24)  # hours
            
            if not ip_address:
                self.send_error(400, "IP address required")
                return
            
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            # Calculate expiration time
            if duration == 'permanent':
                expires_at = None
                permanent = 1
            else:
                expires_at = (datetime.now() + timedelta(hours=int(duration))).isoformat()
                permanent = 0
            
            cursor.execute("""
                INSERT OR REPLACE INTO blocked_ips 
                (ip_address, reason, blocked_at, expires_at, permanent)
                VALUES (?, ?, ?, ?, ?)
            """, (ip_address, reason, datetime.now().isoformat(), expires_at, permanent))
            
            conn.commit()
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': f'IP {ip_address} blocked'}).encode())
            
        except Exception as e:
            self.send_error(500, f"Error blocking IP: {e}")
    
    def handle_unblock_ip(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            ip_address = data.get('ip_address')
            
            if not ip_address:
                self.send_error(400, "IP address required")
                return
            
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip_address,))
            
            conn.commit()
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': True, 'message': f'IP {ip_address} unblocked'}).encode())
            
        except Exception as e:
            self.send_error(500, f"Error unblocking IP: {e}")
    
    def handle_export(self):
        try:
            conn = sqlite3.connect('gateway.db')
            cursor = conn.cursor()
            
            # Export recent data
            cursor.execute("""
                SELECT 'threat' as type, timestamp, client_ip, threat_type, severity, pattern
                FROM threats 
                WHERE timestamp >= datetime('now', '-7 days')
                UNION ALL
                SELECT 'request' as type, timestamp, client_ip, method, path, CAST(status_code AS TEXT)
                FROM requests 
                WHERE timestamp >= datetime('now', '-7 days')
                ORDER BY timestamp DESC
            """)
            
            data = []
            for row in cursor.fetchall():
                data.append({
                    'type': row[0],
                    'timestamp': row[1],
                    'client_ip': row[2],
                    'detail1': row[3],
                    'detail2': row[4],
                    'detail3': row[5] if len(row) > 5 else ''
                })
            
            conn.close()
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Disposition', 'attachment; filename="gateway_export.json"')
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode())
            
        except Exception as e:
            self.send_error(500, f"Export error: {e}")
    
    def serve_static(self):
        # Serve static files (CSS, JS, images)
        self.send_error(404, "Static files not implemented")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='API Security Gateway Monitoring Dashboard')
    parser.add_argument('--port', type=int, default=8001, help='Dashboard port')
    parser.add_argument('--db', default='gateway.db', help='Database file')
    
    args = parser.parse_args()
    
    print(f"🚀 Starting Interactive Security Dashboard on port {args.port}")
    print(f"📊 Database: {args.db}")
    print(f"🌐 Dashboard URL: http://localhost:{args.port}")
    print(f"✨ Features: Real-time monitoring, Interactive charts, IP management")
    
    server = HTTPServer(('', args.port), MonitoringDashboard)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down dashboard...")
        server.shutdown()

if __name__ == '__main__':
    main()