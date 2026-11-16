/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { X } from 'lucide-react';
import { AdminDashboard } from './components/AdminDashboard';
import { AuthModal, MandatoryPasswordChangeModal } from './components/AuthModal';
import { CartCheckoutDrawer } from './components/CartCheckoutDrawer';
import { CustomerDashboard } from './components/CustomerDashboard';
import { Header } from './components/Header';
import { SupportAndLegalPage, TrackOrderPage } from './components/LegalSupportPages';
import { NotificationsPage } from './components/NotificationsPage';
import { ProductDetailModal } from './components/ProductDetailModal';
import { OfflineBanner } from './components/PWAInstallButton';
import { StorefrontView } from './components/StorefrontView';
import { SupplierDashboard } from './components/SupplierDashboard';
import { SupportAssistantWidget } from './components/SupportAssistantWidget';
import { MarketplaceProvider, useMarketplace } from './context/MarketplaceContext';

const MarketplaceShell: React.FC = () => {
  const { activePage, toasts, dismissToast } = useMarketplace();
  const [genderFilter, setGenderFilter] = useState<'ALL' | 'MEN' | 'WOMEN'>('ALL');

  return (
    <div className="min-h-screen bg-[#F8F9FC] text-[#111322]">
      <Header onSelectGender={setGenderFilter} />

      {activePage === 'storefront' && (
        <StorefrontView genderFilter={genderFilter} setGenderFilter={setGenderFilter} />
      )}
      {activePage === 'customer' && <CustomerDashboard />}
      {activePage === 'supplier' && <SupplierDashboard />}
      {activePage === 'admin' && <AdminDashboard />}
      {activePage === 'track' && <TrackOrderPage />}
      {activePage === 'support' && <SupportAndLegalPage />}
      {activePage === 'notifications' && <NotificationsPage />}

      <ProductDetailModal />
      <CartCheckoutDrawer />
      <AuthModal />
      <MandatoryPasswordChangeModal />
      <SupportAssistantWidget />
      <OfflineBanner />

      {/* Toast Queue */}
      <div className="fixed bottom-16 left-3 right-3 sm:left-auto sm:bottom-4 sm:right-4 z-50 space-y-2 sm:w-full sm:max-w-sm pointer-events-none">
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`pointer-events-auto px-4 py-3 text-xs border shadow-md flex items-center justify-between gap-3 ${
              t.type === 'error'
                ? 'bg-red-950 text-white border-red-800'
                : t.type === 'success'
                  ? 'bg-[#111322] text-white border-[#2B3A9F]'
                  : 'bg-white text-[#111322] border-[#E2E5F0]'
            }`}
          >
            <span className="min-w-0 break-words">{t.text}</span>
            <button
              type="button"
              onClick={() => dismissToast(t.id)}
              aria-label="Dismiss notification"
              className="min-h-[32px] min-w-[32px] inline-flex items-center justify-center shrink-0 opacity-70 hover:opacity-100 cursor-pointer"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  );
};

export default function App() {
  return (
    <MarketplaceProvider>
      <MarketplaceShell />
    </MarketplaceProvider>
  );
}
