    
"use client";

import { useState, type FormEvent } from "react";
import { useAuth } from "./context/AuthContext";

type Props = {
  playSound: (type: "click" | "scanStart" | "success" | "error") => void;
};


export default function SecOpsAuthModal({ playSound }: Props) {
  const {
    authModal,
    setAuthModal,
    setUserProfile,
  } = useAuth();

  const [authName, setAuthName] = useState("");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");

  const handleAuthSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    playSound("success");

    const name =
      authName.trim() ||
      authEmail.split("@")[0] ||
      "SecOps Analyst";

    const initials = name
      .split(" ")
      .map((word) => word[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);

    setUserProfile({
      name,
      email: authEmail,
      initials,
    });

    setAuthModal((p) => ({ ...p, open: false }));
  };

  if (!authModal.open) return null;

  return (
    <div
      className="modal-backdrop open"
      id="authModal"
      onClick={() => setAuthModal((p) => ({ ...p, open: false }))}
    >
      <div
        className="modal-window ember-card"
        onClick={(e) => e.stopPropagation()}
      >
        <button
          className="modal-close-btn"
          onClick={() => {
            playSound("click");
            setAuthModal((p) => ({ ...p, open: false }));
          }}
        >
          <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <line x1="18" y1="6" x2="6" y2="18" />
            <line x1="6" y1="18" x2="18" y2="6" />
          </svg>
        </button>

        <div style={{ textAlign: "center", marginBottom: "1rem" }}>
          <h3
            style={{
              fontSize: "1.5rem",
              fontWeight: 800,
              color: "var(--text-primary)",
              fontFamily: "var(--font-heading)",
            }}
          >
            SecOps Analyst Portal
          </h3>

          <p style={{ color: "var(--text-muted)", fontSize: "0.88rem" }}>
            Authenticate for elevated telemetry features
          </p>
        </div>

        <div className="auth-tab-row">
          <button
            className={`auth-tab-btn ${authModal.tab === "signin" ? "active" : ""}`}
            id="tabSignIn"
            onClick={() => {
              playSound("click");
              setAuthModal((p) => ({ ...p, tab: "signin" }));
            }}
          >
            Sign In
          </button>

          <button
            className={`auth-tab-btn ${authModal.tab === "signup" ? "active" : ""}`}
            id="tabSignUp"
            onClick={() => {
              playSound("click");
              setAuthModal((p) => ({ ...p, tab: "signup" }));
            }}
          >
            Create Account
          </button>
        </div>

        <form id="authForm" onSubmit={handleAuthSubmit}>
          {authModal.tab === "signup" && (
            <div className="auth-field" id="nameFieldGroup">
              <label className="auth-label">Full Name</label>

              <input
                type="text"
                id="authName"
                className="auth-input-elem"
                placeholder="Alex Morgan"
                value={authName}
                onChange={(e) => setAuthName(e.target.value)}
                required
              />
            </div>
          )}

          <div className="auth-field">
            <label className="auth-label">SecOps Email</label>

            <input
              type="email"
              id="authEmail"
              className="auth-input-elem"
              placeholder="analyst@cybershield.internal"
              required
              value={authEmail}
              onChange={(e) => setAuthEmail(e.target.value)}
            />
          </div>

          <div className="auth-field">
            <label className="auth-label">Password</label>

            <input
              type="password"
              id="authPassword"
              className="auth-input-elem"
              placeholder="••••••••••••"
              required
              value={authPassword}
              onChange={(e) => setAuthPassword(e.target.value)}
            />
          </div>

          <button
            type="submit"
            className="auth-submit-btn"
            id="authSubmitText"
          >
            {authModal.tab === "signup"
              ? "Register SecOps Account"
              : "Access CyberShield Terminal"}
          </button>
        </form>
      </div>
    </div>
  );
}

