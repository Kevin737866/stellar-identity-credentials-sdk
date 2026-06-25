import React, { useState, useEffect, useCallback } from 'react';
import { 
  Card, 
  CardHeader, 
  CardTitle, 
  CardContent 
} from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { ReputationBadge } from '@/components/ReputationBadge';
import { CredentialWallet } from '@/components/CredentialWallet';
import { ProofRequest } from '@/components/ProofRequest';
import { ComplianceCheck } from '@/components/ComplianceCheck';
import { RegulatoryDashboard } from '@/components/RegulatoryDashboard';
import { useStellarIdentity } from '@/hooks/useStellarIdentity';
import { StellarIdentityConfig } from '@stellar-identity/sdk';
import { Keypair } from 'stellar-sdk';
import { 
  LayoutDashboard, 
  Shield, 
  Zap, 
  CheckSquare, 
  TrendingUp,
  Wallet,
  Settings,
  LogOut,
  Wifi,
  WifiOff,
  Copy,
  Check,
  ChevronDown,
  BarChart3,
  Activity,
  Menu,
  X,
  Bell,
  User,
  Sun,
  Moon,
  Globe,
  Info,
  FileText,
} from 'lucide-react';

interface DashboardProps {
  config: StellarIdentityConfig;
  autoConnect?: boolean;
}

type NetworkType = 'mainnet' | 'testnet' | 'futurenet';

const NETWORK_DETAILS: Record<NetworkType, { label: string; color: string }> = {
  mainnet: { label: 'Mainnet', color: 'bg-green-500' },
  testnet: { label: 'Testnet', color: 'bg-blue-500' },
  futurenet: { label: 'Futurenet', color: 'bg-purple-500' },
};

export const Dashboard: React.FC<DashboardProps> = ({ config, autoConnect = false }) => {
  const { 
    sdk, 
    isConnected, 
    isLoading, 
    error, 
    address, 
    keypair, 
    connect, 
    disconnect,
  } = useStellarIdentity({ config, autoConnect });

  const [activeTab, setActiveTab] = useState('credentials');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [copiedAddress, setCopiedAddress] = useState(false);
  const [network] = useState<NetworkType>(config.network as NetworkType);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
    }
    return 'light';
  });

  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth < 768) {
        setSidebarOpen(false);
      }
    };
    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const toggleTheme = useCallback(() => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    if (newTheme === 'dark') {
      document.documentElement.classList.add('dark');
      document.documentElement.setAttribute('data-theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      document.documentElement.setAttribute('data-theme', 'light');
    }
  }, [theme]);

  const copyAddress = useCallback(() => {
    if (address) {
      navigator.clipboard.writeText(address);
      setCopiedAddress(true);
      setTimeout(() => setCopiedAddress(false), 2000);
    }
  }, [address]);

  const truncateAddress = (addr: string): string => {
    if (addr.length <= 12) return addr;
    return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
  };

  // Loading state
  if (isLoading) {
    return (
      <div style={{
        display: 'flex',
        minHeight: '100vh',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-family)',
        backgroundColor: 'var(--color-bg-secondary)',
        color: 'var(--color-text)',
      }}>
        <Card>
          <CardContent className="p-8">
            <div className="flex flex-col items-center space-y-4">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
              <p className="text-lg font-medium">Initializing Stellar Identity Dashboard</p>
              <p className="text-sm text-gray-500">Connecting to {NETWORK_DETAILS[network].label}...</p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Not connected state
  if (!isConnected || !sdk || !address || !keypair) {
    return (
      <div style={{
        display: 'flex',
        minHeight: '100vh',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-family)',
        backgroundColor: 'var(--color-bg-secondary)',
        color: 'var(--color-text)',
      }}>
        <Card className="max-w-md">
          <CardHeader>
            <CardTitle className="text-center text-xl">
              <Shield className="h-8 w-8 mx-auto mb-3 text-blue-600" />
              Stellar Identity Dashboard
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6 text-center">
            <p className="text-gray-600">
              Connect your wallet to manage your decentralized identity, credentials, and reputation.
            </p>
            <div className="space-y-3">
              <Button onClick={() => connect()} className="w-full">
                <Wallet className="h-4 w-4 mr-2" />
                Create New Keypair
              </Button>
              <p className="text-xs text-gray-400">or enter a secret key below</p>
              <div className="relative">
                <input
                  type="password"
                  id="secret-key"
                  placeholder="Enter your Stellar secret key (starts with S...)"
                  onChange={(e) => { /* handled by enter key */ }}
                  onKeyDown={async (e) => {
                    if (e.key === 'Enter') {
                      try {
                        await connect((e.target as HTMLInputElement).value);
                      } catch {
                        // Error handled by hook
                      }
                    }
                  }}
                  className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                  style={{
                    backgroundColor: 'var(--color-bg)',
                    color: 'var(--color-text)',
                    borderColor: 'var(--color-border)',
                  }}
                />
              </div>
            </div>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  const networkInfo = NETWORK_DETAILS[network];

  return (
    <div style={{
      display: 'flex',
      minHeight: '100vh',
      fontFamily: 'var(--font-family)',
      backgroundColor: 'var(--color-bg-secondary)',
      color: 'var(--color-text)',
    }}>
      {/* Mobile overlay */}
      {mobileMenuOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.5)',
            zIndex: 50,
          }}
          onClick={() => setMobileMenuOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside style={{
        width: sidebarOpen ? '260px' : '64px',
        backgroundColor: 'var(--color-bg)',
        borderRight: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        transition: 'width 300ms ease',
        flexShrink: 0,
        position: 'fixed',
        top: 0,
        left: mobileMenuOpen ? 0 : (sidebarOpen ? 0 : '-260px'),
        bottom: 0,
        zIndex: 40,
      }}
        className="sidebar"
      >
        {/* Sidebar Header */}
        <div style={{
          height: '64px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 1rem',
          borderBottom: '1px solid var(--color-border)',
        }}>
          {sidebarOpen && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield className="h-5 w-5 text-blue-600" />
              <span style={{
                fontSize: '1.125rem',
                fontWeight: 700,
                color: 'var(--color-primary-600)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
              }}>
                Stellar ID
              </span>
            </div>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setSidebarOpen(!sidebarOpen);
              setMobileMenuOpen(false);
            }}
            aria-label={sidebarOpen ? 'Collapse sidebar' : 'Expand sidebar'}
          >
            {sidebarOpen ? <ChevronDown className="h-4 w-4 rotate-90" /> : <ChevronDown className="h-4 w-4 -rotate-90" />}
          </Button>
        </div>

        {/* User Profile Summary */}
        {sidebarOpen && (
          <div style={{
            padding: '1rem',
            borderBottom: '1px solid var(--color-border)',
            backgroundColor: 'var(--color-bg-tertiary)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.75rem' }}>
              <div style={{
                width: '40px',
                height: '40px',
                borderRadius: '50%',
                backgroundColor: 'var(--color-primary-100)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <User className="h-5 w-5 text-blue-600" />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: '0.875rem',
                  fontWeight: 600,
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}>
                  {truncateAddress(address)}
                </div>
                <div style={{
                  fontSize: '0.75rem',
                  color: 'var(--color-text-secondary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.25rem',
                }}>
                  <span style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    backgroundColor: networkInfo.color,
                    display: 'inline-block',
                  }} />
                  {networkInfo.label}
                </div>
              </div>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={copyAddress}
              style={{ width: '100%', justifyContent: 'center', gap: '0.5rem' }}
            >
              {copiedAddress ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
              <span style={{ fontSize: '0.75rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {copiedAddress ? 'Copied!' : address}
              </span>
            </Button>
          </div>
        )}

        {sidebarOpen && (
          <div style={{ padding: '0.5rem 0' }}>
            <ReputationBadge sdk={sdk} address={address} keypair={keypair} size="sm" />
          </div>
        )}

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '0.5rem', overflowY: 'auto' }}>
          {[
            { id: 'credentials', label: 'Credentials', icon: <Shield className="h-4 w-4" /> },
            { id: 'proofs', label: 'Proofs', icon: <Zap className="h-4 w-4" /> },
            { id: 'compliance', label: 'Compliance', icon: <CheckSquare className="h-4 w-4" /> },
            { id: 'reporting', label: 'Reporting', icon: <FileText className="h-4 w-4" /> },
            { id: 'reputation', label: 'Reputation', icon: <TrendingUp className="h-4 w-4" /> },
          ].map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  setActiveTab(item.id);
                  setMobileMenuOpen(false);
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.75rem',
                  width: '100%',
                  padding: '0.75rem',
                  borderRadius: '0.375rem',
                  border: 'none',
                  backgroundColor: isActive ? 'var(--color-primary-50)' : 'transparent',
                  color: isActive ? 'var(--color-primary-700)' : 'var(--color-text-secondary)',
                  fontWeight: isActive ? 500 : 400,
                  fontSize: '0.875rem',
                  fontFamily: 'var(--font-family)',
                  cursor: 'pointer',
                  marginBottom: '0.25rem',
                  textAlign: 'left',
                  transition: 'all 150ms ease',
                }}
              >
                {item.icon}
                {sidebarOpen && <span>{item.label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Sidebar Footer */}
        {sidebarOpen && (
          <div style={{
            padding: '1rem',
            borderTop: '1px solid var(--color-border)',
            display: 'flex',
            flexDirection: 'column',
            gap: '0.5rem',
          }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              fontSize: '0.75rem',
              color: 'var(--color-text-secondary)',
            }}>
              {isConnected ? <Wifi className="h-3 w-3 text-green-500" /> : <WifiOff className="h-3 w-3 text-red-500" />}
              <span>{isConnected ? 'Connected' : 'Disconnected'}</span>
              <span style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                backgroundColor: isConnected ? '#22c55e' : '#ef4444',
              }} />
            </div>
            <Button 
              variant="outline" 
              size="sm" 
              onClick={disconnect}
              style={{ width: '100%' }}
            >
              <LogOut className="h-3 w-3 mr-2" />
              Disconnect
            </Button>
          </div>
        )}
      </aside>

      {/* Main Content */}
      <div style={{
        flex: 1,
        marginLeft: sidebarOpen ? '260px' : '64px',
        transition: 'margin-left 300ms ease',
        display: 'flex',
        flexDirection: 'column',
        minWidth: 0,
      }}>
        {/* Top Bar */}
        <header style={{
          height: '64px',
          backgroundColor: 'var(--color-bg)',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0 1.5rem',
          position: 'sticky',
          top: 0,
          zIndex: 30,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                setMobileMenuOpen(!mobileMenuOpen);
                if (!sidebarOpen && window.innerWidth >= 768) {
                  setSidebarOpen(true);
                }
              }}
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <LayoutDashboard className="h-5 w-5 text-blue-600" />
              <h1 style={{
                fontSize: '1.25rem',
                fontWeight: 600,
                color: 'var(--color-text)',
              }}>
                Dashboard
              </h1>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {/* Network Selector */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: networkInfo.color,
              }} />
              <span style={{
                fontSize: '0.75rem',
                color: 'var(--color-text-secondary)',
                fontWeight: 500,
              }}>
                {networkInfo.label}
              </span>
            </div>

            {/* Theme Toggle */}
            <Button variant="ghost" size="sm" onClick={toggleTheme} aria-label="Toggle theme">
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </Button>

            {/* Notification Bell */}
            <Button variant="ghost" size="sm" aria-label="Notifications">
              <Bell className="h-4 w-4" />
            </Button>

            {/* User Menu */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              padding: '0.25rem 0.75rem',
              borderRadius: '0.375rem',
              backgroundColor: 'var(--color-bg-tertiary)',
              cursor: 'pointer',
            }}>
              <User className="h-4 w-4 text-blue-600" />
              <span style={{ fontSize: '0.8125rem', fontWeight: 500 }}>
                {truncateAddress(address)}
              </span>
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main style={{
          flex: 1,
          padding: '1.5rem',
          maxWidth: '1200px',
          width: '100%',
          margin: '0 auto',
          boxSizing: 'border-box',
        }}>
          {/* Stats Header */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
            gap: '1rem',
            marginBottom: '1.5rem',
          }}>
            <Card>
              <CardContent className="p-4">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>Status</p>
                    <p style={{ fontSize: '1.25rem', fontWeight: 700, color: '#22c55e' }}>Connected</p>
                  </div>
                  <Activity className="h-8 w-8 text-green-100" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>Network</p>
                    <p style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-primary-600)' }}>{networkInfo.label}</p>
                  </div>
                  <Globe className="h-8 w-8 text-blue-100" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div>
                    <p style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>Address</p>
                    <p style={{ fontSize: '0.875rem', fontWeight: 600, fontFamily: 'var(--font-family-mono)' }}>
                      {truncateAddress(address)}
                    </p>
                  </div>
                  <Button variant="ghost" size="sm" onClick={copyAddress}>
                    {copiedAddress ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Tab Navigation */}
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList style={{ marginBottom: '1rem' }}>
              <TabsTrigger value="credentials">
                <Shield className="h-4 w-4 mr-2" />
                Credentials
              </TabsTrigger>
              <TabsTrigger value="proofs">
                <Zap className="h-4 w-4 mr-2" />
                Proofs
              </TabsTrigger>
              <TabsTrigger value="compliance">
                <CheckSquare className="h-4 w-4 mr-2" />
                Compliance
              </TabsTrigger>
              <TabsTrigger value="reporting">
                <FileText className="h-4 w-4 mr-2" />
                Reporting
              </TabsTrigger>
              <TabsTrigger value="reputation">
                <TrendingUp className="h-4 w-4 mr-2" />
                Reputation
              </TabsTrigger>
            </TabsList>

            <TabsContent value="credentials">
              <CredentialWallet sdk={sdk} address={address} keypair={keypair} />
            </TabsContent>

            <TabsContent value="proofs">
              <ProofRequest sdk={sdk} address={address} keypair={keypair} />
            </TabsContent>

            <TabsContent value="compliance">
              <ComplianceCheck sdk={sdk} address={address} keypair={keypair} />
            </TabsContent>

            <TabsContent value="reporting">
              <RegulatoryDashboard sdk={sdk} address={address} keypair={keypair} />
            </TabsContent>

            <TabsContent value="reputation">
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center text-lg">
                    <BarChart3 className="h-5 w-5 mr-2" />
                    Reputation & Analytics
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ReputationBadge sdk={sdk} address={address} keypair={keypair} size="lg" />
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>

          {/* Info footer */}
          <div style={{
            marginTop: '2rem',
            padding: '1rem',
            backgroundColor: 'var(--color-bg)',
            border: '1px solid var(--color-border)',
            borderRadius: '0.5rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.75rem',
            fontSize: '0.8125rem',
            color: 'var(--color-text-secondary)',
          }}>
            <Info className="h-4 w-4 flex-shrink-0" />
            <span>
              Manage your decentralized identity, verifiable credentials, and reputation on the Stellar {networkInfo.label} network.
            </span>
          </div>
        </main>
      </div>

      {/* Responsive styles */}
      <style>{`
        .sidebar {
          transform: translateX(0);
        }
        @media (max-width: 768px) {
          .sidebar {
            transform: translateX(-100%);
          }
          .sidebar[style*="left: 0px"] {
            transform: translateX(0);
          }
          div[style*="margin-left"] {
            margin-left: 0 !important;
          }
        }
        @media (min-width: 769px) and (max-width: 1024px) {
          aside {
            width: 64px !important;
          }
          div[style*="margin-left"] {
            margin-left: 64px !important;
          }
        }
      `}</style>
    </div>
  );
};

export default Dashboard;
