import React, { useState, useEffect } from 'react';
import { Copy, Check, Download, CheckCircle2, Loader2, RefreshCw } from 'lucide-react';
import { apiClient } from '../../zero-trust-auth.jsx';

export function MfaSetupPage() {
  const [step, setStep] = useState(1);
  const [loadingEnroll, setLoadingEnroll] = useState(true);
  const [enrollData, setEnrollData] = useState(null);
  const [code, setCode] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [copiedSecret, setCopiedSecret] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);
  const [error, setError] = useState(null);
  const [recoveryCodes, setRecoveryCodes] = useState([]);

  const initiateEnrollment = async () => {
    setLoadingEnroll(true);
    setError(null);
    try {
      const res = await apiClient.post('/auth/mfa/enroll');
      setEnrollData(res.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not start MFA setup. Please check the backend connection.');
    } finally {
      setLoadingEnroll(false);
    }
  };

  useEffect(() => {
    initiateEnrollment();
  }, []);

  const handleVerifyCode = async (e) => {
    e.preventDefault();
    if (!code || code.trim().length !== 6) {
      setError('Enter a valid 6-digit code.');
      return;
    }
    setVerifying(true);
    setError(null);
    try {
      const res = await apiClient.post('/auth/mfa/verify', { token: code.trim() });
      if (res.data?.recoveryCodes) {
        setRecoveryCodes(res.data.recoveryCodes);
      }
      setStep(3);
    } catch (err) {
      setError(
        err.response?.data?.error ||
        'The code did not match. Check the time on your phone, or enter 123456 in local lab mode.'
      );
    } finally {
      setVerifying(false);
    }
  };

  const copySecret = () => {
    if (!enrollData?.secret) return;
    navigator.clipboard.writeText(enrollData.secret);
    setCopiedSecret(true);
    setTimeout(() => setCopiedSecret(false), 2000);
  };

  const copyAllRecoveryCodes = () => {
    if (!recoveryCodes.length) return;
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2000);
  };

  const downloadRecoveryCodes = () => {
    const text = [
      'ZERO-TRUST LAB - MFA RECOVERY CODES',
      'Created: ' + new Date().toISOString(),
      '------------------------------------------------',
      ...recoveryCodes.map((c, i) => `${i + 1}. ${c}`),
      '------------------------------------------------',
      'Keep these safe. Each code can be used only once if you lose your phone.',
    ].join('\n');
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mfa_recovery_codes_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="space-y-6 max-w-2xl">
      {/* Title & Short Description */}
      <div>
        <h1 className="text-2xl font-semibold text-text-primary tracking-tight">MFA Setup</h1>
        <p className="text-sm text-text-secondary mt-1">
          Add a second step to sign in using an authenticator app.
        </p>
      </div>

      {/* Stepper Header */}
      <div className="grid grid-cols-3 gap-2 bg-surface p-1.5 rounded-control border border-border text-xs">
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-control ${step === 1 ? 'bg-blue-soft text-blue font-medium' : 'text-text-muted'}`}>
          <span className="w-4 h-4 rounded-full border border-current flex items-center justify-center text-[10px]">1</span>
          <span>Scan QR</span>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-control ${step === 2 ? 'bg-blue-soft text-blue font-medium' : 'text-text-muted'}`}>
          <span className="w-4 h-4 rounded-full border border-current flex items-center justify-center text-[10px]">2</span>
          <span>Verify code</span>
        </div>
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-control ${step === 3 ? 'bg-blue-soft text-blue font-medium' : 'text-text-muted'}`}>
          <span className="w-4 h-4 rounded-full border border-current flex items-center justify-center text-[10px]">3</span>
          <span>Recovery</span>
        </div>
      </div>

      {/* Step Container */}
      <div className="bg-surface border border-border rounded-card p-6 shadow-sm">
        {step === 1 && (
          <div className="space-y-6">
            {loadingEnroll ? (
              <div className="py-12 flex flex-col items-center justify-center gap-3 text-text-muted">
                <Loader2 className="w-6 h-6 animate-spin text-blue" />
                <span className="text-xs">Creating secret key and QR code...</span>
              </div>
            ) : error ? (
              <div className="space-y-4">
                <div className="p-3 rounded-control pill-fail text-xs !justify-start">
                  <span>{error}</span>
                </div>
                <button onClick={initiateEnrollment} className="btn-secondary">
                  <RefreshCw className="w-4 h-4" />
                  <span>Try again</span>
                </button>
              </div>
            ) : (
              <>
                <div className="flex flex-col sm:flex-row items-center gap-6">
                  {/* Real Server-Generated QR Code */}
                  <div className="w-44 h-44 bg-surface p-2 rounded-control shrink-0 flex items-center justify-center border border-border shadow-xs">
                    {enrollData?.qrCode ? (
                      <img
                        src={enrollData.qrCode}
                        alt="TOTP Enrollment QR Code"
                        className="w-full h-full object-contain"
                      />
                    ) : (
                      <span className="text-xs text-text-muted">QR not available</span>
                    )}
                  </div>

                  <div className="space-y-3 flex-1 min-w-0">
                    <div className="text-sm font-semibold text-text-primary">Step 1: Scan the QR code</div>
                    <p className="text-xs text-text-secondary leading-relaxed">
                      Open Google Authenticator or another authenticator app on your phone and scan the code.
                    </p>
                    <div className="p-3 bg-raised rounded-control border border-border space-y-1">
                      <span className="text-xs text-text-muted">Or type this secret key manually:</span>
                      <div className="flex items-center justify-between gap-2">
                        <code className="text-xs font-mono font-medium text-blue truncate">
                          {enrollData?.secret || 'Creating...'}
                        </code>
                        <button
                          onClick={copySecret}
                          className="btn-secondary !h-7 !px-2 text-xs shrink-0"
                          aria-label="Copy secret key"
                        >
                          {copiedSecret ? <Check className="w-3.5 h-3.5 text-status-pass" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex justify-end pt-4 border-t border-border">
                  <button
                    onClick={() => setStep(2)}
                    className="btn-primary"
                  >
                    Continue to verification
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {step === 2 && (
          <form onSubmit={handleVerifyCode} className="space-y-4 max-w-sm">
            <div className="text-sm font-semibold text-text-primary">Step 2: Enter the 6-digit code</div>
            <p className="text-xs text-text-secondary">
              Type the 6-digit code shown in your phone app right now.
            </p>

            {error && (
              <div className="p-2.5 rounded-control pill-fail text-xs !justify-start">
                <span>{error}</span>
              </div>
            )}

            <div>
              <input
                type="text"
                maxLength={6}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                placeholder="000000"
                autoFocus
                className="w-full text-center text-xl font-mono tracking-widest h-12 bg-surface border border-border rounded-control text-text-primary focus:border-blue focus:outline-none"
              />
              <span className="block text-[11px] text-text-muted mt-1.5 text-center font-mono">
                Lab testing fallback: 123456
              </span>
            </div>

            <div className="flex items-center justify-between pt-2">
              <button
                type="button"
                onClick={() => setStep(1)}
                className="btn-secondary !h-9 text-xs"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={verifying || code.trim().length !== 6}
                className="btn-primary !h-9 text-xs"
              >
                {verifying ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Checking...</span>
                  </>
                ) : (
                  <span>Verify and turn on</span>
                )}
              </button>
            </div>
          </form>
        )}

        {step === 3 && (
          <div className="space-y-5">
            <div className="flex items-center gap-3 text-status-pass border-b border-border pb-4">
              <CheckCircle2 className="w-6 h-6 shrink-0" />
              <div>
                <div className="text-sm font-semibold text-text-primary">
                  Two-factor authentication is now on
                </div>
                <div className="text-xs text-text-secondary">
                  Your account is protected with a rolling 6-digit code.
                </div>
              </div>
            </div>

            <div>
              <div className="text-xs font-semibold uppercase text-text-muted tracking-wider mb-1">
                One-time recovery codes
              </div>
              <p className="text-xs text-text-secondary mb-3">
                Save these codes in a safe place. You can use each code once if you lose your phone.
              </p>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 bg-raised p-4 rounded-control border border-border">
                {recoveryCodes.length > 0 ? (
                  recoveryCodes.map((rc, idx) => (
                    <div
                      key={idx}
                      className="p-2 bg-surface rounded border border-border text-center font-mono text-xs text-text-primary"
                    >
                      {rc}
                    </div>
                  ))
                ) : (
                  <div className="col-span-4 text-center text-xs text-text-muted py-2">
                    Recovery codes saved on server.
                  </div>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-border">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={copyAllRecoveryCodes}
                  className="btn-secondary !h-9 text-xs"
                >
                  {copiedCodes ? <Check className="w-3.5 h-3.5 text-status-pass" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedCodes ? 'Copied codes' : 'Copy codes'}</span>
                </button>
                <button
                  type="button"
                  onClick={downloadRecoveryCodes}
                  className="btn-secondary !h-9 text-xs"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .txt</span>
                </button>
              </div>

              <button
                type="button"
                onClick={() => {
                  setStep(1);
                  initiateEnrollment();
                }}
                className="btn-primary !h-9 text-xs"
              >
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
