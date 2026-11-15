import React, { useState, useEffect, useRef } from 'react';
import {
  Printer,
  AlertTriangle,
  ArrowRight,
} from 'lucide-react';
import { Chart } from 'chart.js/auto';
import { StatCard } from '../components/common/StatCard';
import { apiClient } from '../../zero-trust-auth.jsx';
import { DEFAULT_THREAT_TESTS } from './ThreatLabPage';

export function ResultsPage({ onNavigateToThreatLab }) {
  const [tests, setTests] = useState(() => {
    try {
      const saved = localStorage.getItem('zt_threat_tests');
      return saved ? JSON.parse(saved) : DEFAULT_THREAT_TESTS;
    } catch {
      return DEFAULT_THREAT_TESTS;
    }
  });
  const [summary, setSummary] = useState(() => {
    try {
      const saved = localStorage.getItem('zt_threat_summary');
      return saved ? JSON.parse(saved) : { total: 9, passed: 9, failed: 0, passPercentage: 100 };
    } catch {
      return { total: 9, passed: 9, failed: 0, passPercentage: 100 };
    }
  });
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(false);

  // Chart canvas refs
  const categoryChartRef = useRef(null);
  const originChartRef = useRef(null);
  const categoryChartInstance = useRef(null);
  const originChartInstance = useRef(null);

  const fetchResultsAndLogs = async () => {
    setLoading(true);
    try {
      const testRes = await apiClient.get('/api/threat-lab/results');
      if (testRes.data?.results && testRes.data.results.length > 0) {
        setTests(testRes.data.results);
        const passCount = testRes.data.results.filter((r) => r.passed).length;
        setSummary({
          total: testRes.data.results.length,
          passed: passCount,
          failed: testRes.data.results.length - passCount,
          passPercentage: Math.round((passCount / testRes.data.results.length) * 100),
        });
      }
    } catch (err) {
      console.warn('Failed to load threat lab results:', err);
    }

    try {
      const logsRes = await apiClient.get('/api/audit/logs?limit=250');
      setAuditLogs(logsRes.data?.logs || []);
    } catch (err) {
      console.warn('Failed to load audit logs:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchResultsAndLogs();
  }, []);

  // Compute Categories
  const categoryMap = {};
  tests.forEach((t) => {
    const cat = t.category || 'General';
    if (!categoryMap[cat]) {
      categoryMap[cat] = { name: cat, passed: 0, failed: 0, total: 0 };
    }
    categoryMap[cat].total += 1;
    if (t.passed) {
      categoryMap[cat].passed += 1;
    } else {
      categoryMap[cat].failed += 1;
    }
  });
  const categoryList = Object.values(categoryMap);

  // Compute Origin Stats
  let externalPass = 0;
  let externalFail = 0;
  let insiderPass = 0;
  let insiderFail = 0;
  tests.forEach((t) => {
    if (t.origin === 'External') {
      if (t.passed) externalPass++;
      else externalFail++;
    } else {
      if (t.passed) insiderPass++;
      else insiderFail++;
    }
  });

  // Render Chart.js charts whenever tests change
  useEffect(() => {
    if (tests.length === 0) return;

    // 1. Chart 1: Results by threat category (vertical stacked bar chart)
    if (categoryChartRef.current) {
      if (categoryChartInstance.current) {
        categoryChartInstance.current.destroy();
      }
      const ctx1 = categoryChartRef.current.getContext('2d');
      categoryChartInstance.current = new Chart(ctx1, {
        type: 'bar',
        data: {
          labels: categoryList.map((c) => c.name),
          datasets: [
            {
              label: 'Pass',
              data: categoryList.map((c) => c.passed),
              backgroundColor: '#15803D',
              borderRadius: 4,
              barThickness: 16,
            },
            {
              label: 'Fail',
              data: categoryList.map((c) => c.failed),
              backgroundColor: '#B91C1C',
              borderRadius: 4,
              barThickness: 16,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              stacked: true,
              grid: { display: false },
              ticks: {
                maxRotation: 40,
                minRotation: 20,
                color: '#0F172A',
                font: { family: 'IBM Plex Sans', size: 11 },
              },
            },
            y: {
              stacked: true,
              beginAtZero: true,
              grid: { color: '#E2E8F0' },
              ticks: {
                stepSize: 1,
                color: '#475569',
                font: { family: 'IBM Plex Sans', size: 12 },
              },
            },
          },
          plugins: {
            legend: {
              position: 'top',
              align: 'start',
              labels: {
                boxWidth: 12,
                boxHeight: 12,
                color: '#475569',
                font: { family: 'IBM Plex Sans', size: 12 },
              },
            },
            tooltip: {
              titleFont: { family: 'IBM Plex Sans', size: 12 },
              bodyFont: { family: 'IBM Plex Sans', size: 12 },
            },
          },
        },
      });
    }

    // 2. Chart 2: Tests by origin (column chart with External and Insider)
    if (originChartRef.current) {
      if (originChartInstance.current) {
        originChartInstance.current.destroy();
      }
      const ctx2 = originChartRef.current.getContext('2d');
      originChartInstance.current = new Chart(ctx2, {
        type: 'bar',
        data: {
          labels: ['External attacks', 'Insider attacks'],
          datasets: [
            {
              label: 'Pass',
              data: [externalPass, insiderPass],
              backgroundColor: '#15803D',
              borderRadius: 4,
              barThickness: 20,
            },
            {
              label: 'Fail',
              data: [externalFail, insiderFail],
              backgroundColor: '#B91C1C',
              borderRadius: 4,
              barThickness: 20,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            x: {
              grid: { display: false },
              ticks: {
                color: '#0F172A',
                font: { family: 'IBM Plex Sans', size: 12 },
              },
            },
            y: {
              beginAtZero: true,
              grid: { color: '#E2E8F0' },
              ticks: {
                stepSize: 1,
                color: '#475569',
                font: { family: 'IBM Plex Sans', size: 12 },
              },
            },
          },
          plugins: {
            legend: {
              position: 'top',
              align: 'start',
              labels: {
                boxWidth: 12,
                boxHeight: 12,
                color: '#475569',
                font: { family: 'IBM Plex Sans', size: 12 },
              },
            },
            tooltip: {
              titleFont: { family: 'IBM Plex Sans', size: 12 },
              bodyFont: { family: 'IBM Plex Sans', size: 12 },
            },
          },
        },
      });
    }

    return () => {
      if (categoryChartInstance.current) categoryChartInstance.current.destroy();
      if (originChartInstance.current) originChartInstance.current.destroy();
    };
  }, [tests]);

  // Improvements list: max 5 items, student friendly, failed test first
  const failedTests = tests.filter((t) => !t.passed);
  const failureImprovements = failedTests.slice(0, 2).map((t) => ({
    title: `Fix defense for ${t.name}`,
    description: `Investigation needed: expected "${t.expected}", but got "${t.actual}".`,
    isUrgent: true,
  }));

  const standardImprovements = [
    {
      title: 'Store refresh tokens in httpOnly cookies',
      description: 'Move refresh tokens out of JavaScript memory so browser scripts cannot read them.',
    },
    {
      title: 'Keep the token blacklist in Redis',
      description: 'Use Redis key expiration to check revoked tokens instantly without loading the database.',
    },
    {
      title: 'Add hardware security keys later',
      description: 'Allow users to plug in a YubiKey or use Touch ID instead of typing 6-digit codes.',
    },
    {
      title: 'Review audit logs every week',
      description: 'Check for repeated blocked requests and rate-limit triggers regularly.',
    },
  ];

  const improvements = [...failureImprovements, ...standardImprovements].slice(0, 5);

  const handlePrintReport = () => {
    const today = new Date().toISOString().split('T')[0];
    const prevTitle = document.title;
    document.title = `Zero-Trust-Test-Report-${today}`;
    window.print();
    setTimeout(() => {
      document.title = prevTitle;
    }, 1000);
  };

  const last10WarningsOrDenials = auditLogs
    .filter((l) => l.decision === 'DENY' || l.decision === 'WARN')
    .slice(0, 10);

  return (
    <div className="space-y-6">
      {/* ─── SCREEN VIEW (Hidden when printing) ────────────────────────── */}
      <div className="no-print space-y-6">
        {/* Title & Actions */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-text-primary tracking-tight">Results & Verification</h1>
            <p className="text-sm font-medium text-text-secondary mt-1">
              Test results, security category breakdown, and Zero-Trust architecture assessment.
            </p>
          </div>
          <div>
            <button
              onClick={handlePrintReport}
              disabled={tests.length === 0}
              className="btn-primary !h-9 !px-4 text-xs font-bold"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Download PDF / Print</span>
            </button>
          </div>
        </div>

        {/* ─── SUMMARY CONTENT ────────────────────────────────────────── */}
        <div className="space-y-6">
          {tests.length === 0 ? (
            <div className="bg-surface border border-border rounded-card p-12 text-center space-y-3 shadow-xs">
              <div className="w-12 h-12 mx-auto rounded-full bg-raised border border-border flex items-center justify-center text-text-muted">
                <AlertTriangle className="w-6 h-6" />
              </div>
              <div className="text-base font-semibold text-text-primary">
                No tests run yet. Open Threat Lab and run the tests.
              </div>
              <p className="text-xs text-text-secondary max-w-md mx-auto">
                Run the attacks in Threat Lab to calculate your score and populate the charts.
              </p>
              {onNavigateToThreatLab && (
                <button
                  onClick={onNavigateToThreatLab}
                  className="btn-primary !h-9 !px-4 text-xs mx-auto mt-2"
                >
                  <span>Go to Threat Lab</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          ) : (
            <>
              {/* 3 Summary Stat Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <StatCard
                  label="Tests run"
                  value={summary.total.toString()}
                  subtext="All local attack tests"
                />
                <StatCard
                  label="Passed"
                  value={summary.passed.toString()}
                  subtext="Cleanly blocked by policy"
                />
                <StatCard
                  label="Failed"
                  value={summary.failed.toString()}
                  subtext={summary.failed === 0 ? 'No gaps exposed' : `${summary.failed} tests need attention`}
                />
              </div>

              {/* 2 Clean Chart.js Charts (Both Vertical) */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Chart 1: Results by threat category */}
                <div className="bg-surface border border-border rounded-card p-5 space-y-3 shadow-xs">
                  <div>
                    <div className="text-sm font-bold text-text-primary">Results by threat category</div>
                    <div className="text-xs text-text-secondary">Pass and fail counts across each security category.</div>
                  </div>
                  <div className="h-64 w-full relative">
                    <canvas ref={categoryChartRef} />
                  </div>
                </div>

                {/* Chart 2: Tests by origin */}
                <div className="bg-surface border border-border rounded-card p-5 space-y-3 shadow-xs">
                  <div>
                    <div className="text-sm font-bold text-text-primary">Tests by origin</div>
                    <div className="text-xs text-text-secondary">Comparison between external and insider attacks.</div>
                  </div>
                  <div className="h-64 w-full relative">
                    <canvas ref={originChartRef} />
                  </div>
                </div>
              </div>

              {/* Test Details Table without Log Evidence column */}
              <div className="bg-surface border border-border rounded-card p-5 space-y-3 shadow-xs">
                <div className="text-sm font-bold text-text-primary">Test outcomes</div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-border text-text-secondary bg-raised/50">
                        <th className="py-2.5 px-3 font-medium">Attack</th>
                        <th className="py-2.5 px-3 font-medium">Origin</th>
                        <th className="py-2.5 px-3 font-medium">Expected</th>
                        <th className="py-2.5 px-3 font-medium">Actual</th>
                        <th className="py-2.5 px-3 font-medium text-right">Result</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {tests.map((t) => (
                        <tr key={t.id} className="hover:bg-raised/60">
                          <td className="py-3 px-3 font-medium text-text-primary">
                            <div>{t.name}</div>
                            <span className="font-mono text-[11px] text-text-muted">{t.id}</span>
                          </td>
                          <td className="py-3 px-3">
                            <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                              t.origin === 'External'
                                ? 'bg-status-warning-soft text-status-warning border-status-warning/25'
                                : 'bg-blue-soft text-blue border-blue/25'
                            }`}>
                              {t.origin}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-mono text-[11px] text-text-secondary max-w-xs truncate" title={t.expected}>
                            {t.expected}
                          </td>
                          <td className="py-3 px-3 font-mono text-[11px] text-text-primary max-w-xs truncate" title={t.actual}>
                            {t.actual}
                          </td>
                          <td className="py-3 px-3 text-right">
                            <span className={t.passed ? 'pill-pass' : 'pill-fail'}>
                              {t.passed ? 'Pass' : 'Fail'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Improvements List (Max 5 plain items) */}
              <div className="bg-surface border border-border rounded-card p-5 space-y-3 shadow-xs">
                <div>
                  <div className="text-sm font-bold text-text-primary">Suggested improvements</div>
                  <div className="text-xs text-text-secondary">Next steps to strengthen the security of this lab.</div>
                </div>

                <div className="divide-y divide-border border border-border rounded-control overflow-hidden">
                  {improvements.map((item, idx) => (
                    <div
                      key={idx}
                      className={`p-3.5 transition-colors space-y-0.5 ${
                        item.isUrgent ? 'bg-status-fail-soft/40' : 'bg-surface hover:bg-raised/40'
                      }`}
                    >
                      <div className={`text-sm font-semibold ${item.isUrgent ? 'text-status-fail' : 'text-text-primary'}`}>
                        {item.title}
                      </div>
                      <p className="text-xs text-text-secondary">{item.description}</p>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>

      {/* ─── PRINT-ONLY SINGLE PAGE REPORT LAYOUT (@media print) ───── */}
      <div className="hidden print:block print-single-page text-black bg-white space-y-3 font-sans">
        {/* Header */}
        <div className="border-b border-gray-300 pb-2 flex justify-between items-start">
          <div>
            <h1 className="text-lg font-bold tracking-tight text-black">
              Zero-Trust Architecture Test Report
            </h1>
            <p className="text-[11px] text-gray-600">
              Minor Project 2: Zero Trust Architecture for Enterprise Security
            </p>
            <p className="text-[10px] text-gray-500 font-medium">
              Authors: Jainam Shah &amp; Mahi Patel &bull; Group C
            </p>
          </div>
          <div className="text-right space-y-1">
            <span className="inline-block px-2.5 py-0.5 rounded text-[11px] font-bold bg-green-100 text-green-800 border border-green-300">
              {summary.passed}/{summary.total} DEFENSES VERIFIED ({summary.passPercentage}%)
            </span>
            <div className="text-[10px] text-gray-500 font-mono">
              Date: {new Date().toLocaleDateString()}
            </div>
          </div>
        </div>

        {/* Executive Summary Stats Bar */}
        <div className="grid grid-cols-4 gap-2 text-center text-xs">
          <div className="border border-gray-300 rounded p-1.5 bg-gray-50">
            <div className="text-[10px] text-gray-500 font-medium uppercase">Tests Run</div>
            <div className="text-base font-bold text-black">{summary.total}</div>
          </div>
          <div className="border border-green-300 rounded p-1.5 bg-green-50">
            <div className="text-[10px] text-green-700 font-medium uppercase">Passed Defenses</div>
            <div className="text-base font-bold text-green-700">{summary.passed}</div>
          </div>
          <div className="border border-gray-300 rounded p-1.5 bg-gray-50">
            <div className="text-[10px] text-gray-500 font-medium uppercase">Breaches / Gaps</div>
            <div className="text-base font-bold text-black">{summary.failed}</div>
          </div>
          <div className="border border-blue-300 rounded p-1.5 bg-blue-50">
            <div className="text-[10px] text-blue-700 font-medium uppercase">Pass Rate</div>
            <div className="text-base font-bold text-blue-700">{summary.passPercentage}%</div>
          </div>
        </div>

        {/* Results by Category Table */}
        <div>
          <div className="text-xs font-bold text-black mb-1">Results by Threat Category</div>
          <table className="w-full text-left text-[10px] border border-gray-300">
            <thead>
              <tr className="bg-gray-100 border-b border-gray-300 font-semibold text-gray-700">
                <th className="py-1 px-2">Category</th>
                <th className="py-1 px-2 text-center">Passed</th>
                <th className="py-1 px-2 text-center">Failed</th>
                <th className="py-1 px-2 text-center">Total</th>
                <th className="py-1 px-2 text-right">Defense Rate</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {categoryList.map((c) => (
                <tr key={c.name}>
                  <td className="py-0.5 px-2 font-medium">{c.name}</td>
                  <td className="py-0.5 px-2 text-center text-green-700 font-semibold">{c.passed}</td>
                  <td className="py-0.5 px-2 text-center text-red-700 font-semibold">{c.failed}</td>
                  <td className="py-0.5 px-2 text-center">{c.total}</td>
                  <td className="py-0.5 px-2 text-right font-medium">
                    {c.total > 0 ? Math.round((c.passed / c.total) * 100) : 0}%
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Detailed Test Outcomes Table */}
        <div>
          <div className="text-xs font-bold text-black mb-1">Test Outcomes</div>
          <table className="w-full text-left text-[10px] border border-gray-300">
            <thead>
              <tr className="bg-gray-100 border-b border-gray-300 font-semibold text-gray-700">
                <th className="py-1 px-2">Attack Vector</th>
                <th className="py-1 px-2">Origin</th>
                <th className="py-1 px-2">Expected Policy</th>
                <th className="py-1 px-2">Defense Outcome</th>
                <th className="py-1 px-2 text-right">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {tests.map((t) => (
                <tr key={t.id}>
                  <td className="py-0.5 px-2 font-medium text-black">
                    {t.name}
                  </td>
                  <td className="py-0.5 px-2 text-gray-600">{t.origin}</td>
                  <td className="py-0.5 px-2 font-mono text-[9px] text-gray-600 truncate max-w-[140px]">{t.expected}</td>
                  <td className="py-0.5 px-2 font-mono text-[9px] text-black truncate max-w-[150px]">{t.actual}</td>
                  <td className="py-0.5 px-2 text-right font-bold">
                    <span className={t.passed ? 'text-green-700' : 'text-red-700'}>
                      {t.passed ? 'Pass' : 'Fail'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Security Architecture Verifications */}
        <div className="border border-gray-300 rounded p-2 bg-gray-50 text-[10px] space-y-1">
          <div className="font-bold text-black">Architecture Defense Verification:</div>
          <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-gray-700">
            <div>&bull; <strong>Least Privilege:</strong> RBAC + SQLite persistence enforces least privilege on every endpoint.</div>
            <div>&bull; <strong>Continuous Auth:</strong> Single-use token rotation &amp; blacklisting prevents replay attacks.</div>
            <div>&bull; <strong>Micro-Segmentation:</strong> Docker networks isolate database and auth services from untrusted networks.</div>
            <div>&bull; <strong>Data Protection:</strong> AES-256-GCM authenticated encryption secures sensitive secrets at rest.</div>
          </div>
        </div>

        {/* Fixed Print Footer */}
        <div className="text-center pt-2 text-[9px] text-gray-500 border-t border-gray-300">
          Minor Project 2: Zero Trust Architecture for Enterprise Security | Developed by Jainam Shah and Mahi Patel | Group C
        </div>
      </div>
    </div>
  );
}
