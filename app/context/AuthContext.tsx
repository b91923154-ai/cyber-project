
"use client";

import {
  createContext,
  useContext,
  useState,
  type ReactNode,
  type Dispatch,
  type SetStateAction,
} from "react";

import type { AuditReport } from "../api/audit/route";

export interface UserProfile {
  name: string;
  email: string;
  initials: string;
}

export type AuthModalState = {
  open: boolean;
  tab: "signin" | "signup";
};

export type RemedModalState = {
  open: boolean;
  header: string;
  tab: "nginx" | "apache" | "cloudflare" | "nextjs" | "caddy";
};

interface AuthContextType {
  authModal: AuthModalState;
  setAuthModal: Dispatch<SetStateAction<AuthModalState>>;

  userProfile: UserProfile | null;
  setUserProfile: Dispatch<SetStateAction<UserProfile | null>>;

  isProfileDropdownOpen: boolean;
  setIsProfileDropdownOpen: Dispatch<SetStateAction<boolean>>;

  isHistoryOpen: boolean;
  setIsHistoryOpen: Dispatch<SetStateAction<boolean>>;

  scanHistory: AuditReport[];
  setScanHistory: Dispatch<SetStateAction<AuditReport[]>>;

  remedModal: RemedModalState;
  setRemedModal: Dispatch<SetStateAction<RemedModalState>>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authModal, setAuthModal] = useState<AuthModalState>({
    open: false,
    tab: "signin",
  });

  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);

  const [isProfileDropdownOpen, setIsProfileDropdownOpen] = useState(false);

  const [isHistoryOpen, setIsHistoryOpen] = useState(false);

  const [scanHistory, setScanHistory] = useState<AuditReport[]>([]);

  const [remedModal, setRemedModal] = useState<RemedModalState>({
    open: false,
    header: "Strict-Transport-Security",
    tab: "nginx",
  });

  return (
    <AuthContext.Provider
      value={{
        authModal,
        setAuthModal,
        userProfile,
        setUserProfile,
        isProfileDropdownOpen,
        setIsProfileDropdownOpen,
        isHistoryOpen,
        setIsHistoryOpen,
        scanHistory,
        setScanHistory,
        remedModal,
        setRemedModal,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used inside AuthProvider");
  }

  return context;
}
