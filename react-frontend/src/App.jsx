import React, { useState } from 'react';
import { AuthProvider, useAuth, apiClient } from '../zero-trust-auth.jsx';
import { Shell } from './components/layout/Shell';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { SessionPage } from './pages/SessionPage';
import { MfaSetupPage } from './pages/MfaSetupPage';
import { UsersRolesPage } from './pages/UsersRolesPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { NetworkSegmentationPage } from './pages/NetworkSegmentationPage';
import { EncryptionPage } from './pages/EncryptionPage';
import { ThreatLabPage } from './pages/ThreatLabPage';
import { ResultsPage } from './pages/ResultsPage';

function MainApp() {
  const { user, login, logout, logoutAll, trustDevice, mfaRequired, newDevice } = useAuth();
  const [activePage, setActivePage] = useState('dashboard');
  const [loadingLogin, setLoadingLogin] = useState(false);
  const [loginError, setLoginError] = useState(null);

  const handleLogin = async (identifier, password, mfaCode) => {
    setLoadingLogin(true);
    setLoginError(null);
    try {
      const res = await login(identifier, password, mfaCode || null);
      if (res?.mfaRequired) {
        setLoginError('MFA code required: Enter your 6-digit rolling authenticator code.');
      }
    } catch (err) {
      const detail =
        err.response?.data?.error ||
        err.response?.data?.detail ||
        err.message ||
        'Authentication verification failed';
      setLoginError(detail);
    } finally {
      setLoadingLogin(false);
    }
  };

  // If user is not logged in, show centered Login page
  if (!user) {
    return (
      <LoginPage
        onLogin={handleLogin}
        loading={loadingLogin}
        error={loginError}
        mfaRequired={mfaRequired}
      />
    );
  }

  // Active Authenticated Shell (9 sidebar items)
  return (
    <Shell
      activePage={activePage}
      setActivePage={setActivePage}
      user={user}
      onLogout={logout}
    >
      {activePage === 'dashboard' && <DashboardPage />}

      {activePage === 'session' && (
        <SessionPage
          user={user}
          onTrustDevice={trustDevice}
          newDevice={newDevice}
        />
      )}

      {activePage === 'mfa-setup' && <MfaSetupPage />}

      {activePage === 'users-roles' && <UsersRolesPage />}

      {activePage === 'policies' && <PoliciesPage />}

      {activePage === 'network-lab' && <NetworkSegmentationPage />}

      {activePage === 'encryption' && <EncryptionPage />}

      {activePage === 'threat-lab' && (
        <ThreatLabPage onNavigateToResults={() => setActivePage('results')} />
      )}

      {activePage === 'results' && (
        <ResultsPage onNavigateToThreatLab={() => setActivePage('threat-lab')} />
      )}
    </Shell>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <MainApp />
    </AuthProvider>
  );
}
