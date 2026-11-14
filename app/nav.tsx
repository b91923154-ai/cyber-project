
"use client";

import { useState, useEffect } from "react";
import { useAuth } from "./context/AuthContext";

export default function Nav() {
  const [theme, setTheme] = useState<"dark" | "light">("dark");

  const {
    setAuthModal,
    setIsHistoryOpen,
    setIsProfileDropdownOpen,
    setUserProfile,
    scanHistory,
    userProfile,
    isProfileDropdownOpen,
  } = useAuth();

  // Load saved theme when component mounts
  useEffect(() => {
    const savedTheme = localStorage.getItem("cybershield-theme");

    if (savedTheme === "dark" || savedTheme === "light") {
      setTheme(savedTheme);
      document.documentElement.setAttribute("data-theme", savedTheme);
    } else {
      document.documentElement.setAttribute("data-theme", "dark");
    }
  }, []);

  // Generate initials from user's name
  const initials = userProfile
    ? userProfile.name
        .trim()
        .split(/\s+/)
        .map((word) => word[0])
        .slice(0, 2)
        .join("")
        .toUpperCase()
    : "";

  // Sign Out
  const handleSignOut = () => {
    setUserProfile(null);
    setIsProfileDropdownOpen(false);
  };

  // Toggle Theme
  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";

    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("cybershield-theme", next);
  };

  return (
    <nav className="nav-bar">
      <div className="nav-inner">

        {/* Brand Logo */}
        <a
          href="#"
          className="nav-brand"
          onClick={(e) => {
            e.preventDefault();
            window.scrollTo({ top: 0, behavior: "smooth" });
          }}
        >
          <div className="brand-logo-mark">
            <div className="logo-mark-glow" />

            <div className="logo-mark-frame">
              <svg
                viewBox="0 0 32 32"
                fill="none"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  d="M16 3L6 7V15C6 21.5 10.3 27.5 16 29C21.7 27.5 26 21.5 26 15V7L16 3Z"
                  stroke="url(#navShieldGrad)"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />

                <path
                  d="M16 8L10 11V15C10 19.5 12.6 23.6 16 24.8C19.4 23.6 22 19.5 22 15V11L16 8Z"
                  fill="url(#navShieldInnerGrad)"
                  opacity="0.45"
                />

                <circle cx="16" cy="16" r="3" fill="#ff731d" />

                <line x1="16" y1="11" x2="16" y2="13" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                <line x1="16" y1="19" x2="16" y2="21" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                <line x1="11" y1="16" x2="13" y2="16" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />
                <line x1="19" y1="16" x2="21" y2="16" stroke="#ff731d" strokeWidth="1.8" strokeLinecap="round" />

                <defs>
                  <linearGradient
                    id="navShieldGrad"
                    x1="6"
                    y1="3"
                    x2="26"
                    y2="29"
                    gradientUnits="userSpaceOnUse"
                  >
                    <stop stopColor="#ff3b30" />
                    <stop offset="0.5" stopColor="#ff731d" />
                    <stop offset="1" stopColor="#ffb300" />
                  </linearGradient>

                  <linearGradient
                    id="navShieldInnerGrad"
                    x1="10"
                    y1="8"
                    x2="22"
                    y2="24.8"
                    gradientUnits="userSpaceOnUse"
                  >
                    <stop stopColor="#ff731d" />
                    <stop offset="1" stopColor="#ff3b30" stopOpacity="0" />
                  </linearGradient>
                </defs>
              </svg>
            </div>
          </div>

          <div className="brand-text-wrapper">
            <span className="nav-brand-text">CYBERSHIELD</span>
            <span className="nav-brand-sub">Threat Intelligence</span>
          </div>
        </a>

        {/* Navigation Actions */}
        <div className="nav-actions">

          {/* Scan History */}
          <div
            className="chromatic-capsule"
            style={{ position: "relative" }}
          >
            <button
              className="chromatic-circle-btn"
              id="historyDrawerBtn"
              onClick={() => setIsHistoryOpen(true)}
              title="View Audit History [H]"
              aria-label="Scan history"
            >
              <div className="chromatic-circle-inner">
                <svg
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <circle cx="12" cy="12" r="10" />
                  <polyline points="12 6 12 12 16 14" />
                </svg>
              </div>
            </button>

            <span className="history-count-badge" id="historyCounter">
              {scanHistory.length}
            </span>
          </div>

          {/* Theme Switcher */}
          <div className="chromatic-capsule">
            <button
              className="chromatic-circle-btn"
              id="themeToggleBtn"
              onClick={toggleTheme}
              title="Toggle Theme"
              aria-label="Toggle theme"
            >
              <div className="chromatic-circle-inner">
                {theme === "light" ? (
                  <svg
                    className="theme-icon-sun"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <circle cx="12" cy="12" r="5" />
                    <line x1="12" y1="1" x2="12" y2="3" />
                    <line x1="12" y1="21" x2="12" y2="23" />
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64" />
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78" />
                    <line x1="1" y1="12" x2="3" y2="12" />
                    <line x1="21" y1="12" x2="23" y2="12" />
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36" />
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22" />
                  </svg>
                ) : (
                  <svg
                    className="theme-icon-moon"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth="2.2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
                  </svg>
                )}
              </div>
            </button>
          </div>

          {/* Login Button / User Profile */}
          {!userProfile ? (
            <button
              className="auth-pill-btn"
              id="openAuthBtn"
              onClick={() => {
                setAuthModal({
                  open: true,
                  tab: "signin",
                });
              }}
            >
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>

              <span>SecOps Login</span>
            </button>
          ) : (
            <div
              className="profile-hub"
              id="profileHub"
              style={{ position: "relative" }}
            >

              {/* Profile Button */}
              <div className="chromatic-capsule">
                <button
                  className="chromatic-circle-btn"
                  id="profileMenuBtn"
                  onClick={(e) => {
                    e.stopPropagation();

                    setIsProfileDropdownOpen((prev) => !prev);
                  }}
                  aria-label="Open profile menu"
                  aria-expanded={isProfileDropdownOpen}
                >
                  <div
                    className="chromatic-circle-inner"
                    id="userInitials"
                    style={{
                      fontWeight: 800,
                      fontFamily: "var(--font-mono)",
                      fontSize: "0.85rem",
                    }}
                  >
                    {initials}
                  </div>
                </button>

                <span className="online-dot" />
              </div>

              {/* Profile Dropdown */}
              {isProfileDropdownOpen && (
                <div
                  className="profile-dropdown ember-card open"
                  id="profileDropdown"
                  onClick={(e) => e.stopPropagation()}
                >

                  {/* User Information */}
                  <div className="profile-dropdown-header">
                    <div
                      className="profile-dropdown-avatar"
                      id="dropdownAvatar"
                    >
                      {initials}
                    </div>

                    <div className="profile-dropdown-info">
                      <h4 id="dropdownUserName">
                        {userProfile.name}
                      </h4>

                      <span className="role-badge">
                        Lead Analyst
                      </span>
                    </div>
                  </div>

                  {/* Audit History */}
                  <button
                    className="profile-dropdown-item"
                    onClick={() => {
                      setIsHistoryOpen(true);
                      setIsProfileDropdownOpen(false);
                    }}
                  >
                    <svg
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <circle cx="12" cy="12" r="10" />
                      <polyline points="12 6 12 12 16 14" />
                    </svg>

                    Audit History
                  </button>

                  {/* API Credentials */}
                  <button
                    className="profile-dropdown-item"
                    onClick={() =>
                      alert(
                        `API Integration Key: CS-SEC-${Math.random()
                          .toString(36)
                          .substring(2, 10)
                          .toUpperCase()}`
                      )
                    }
                  >
                    <svg
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <path d="M15 7a2 2 0 0 1 2 2m4 0a6 6 0 0 1-7.743 5.743L11 17H9v2H7v2H4a1 1 0 0 1-1-1v-2.586a1 1 0 0 1 .293-.707l5.964-5.964A6 6 0 1 1 21 9z" />
                    </svg>

                    API Credentials
                  </button>

                  <div className="profile-dropdown-divider" />

                  {/* Sign Out */}
                  <button
                    className="profile-dropdown-item danger"
                    id="signOutBtn"
                    onClick={handleSignOut}
                  >
                    <svg
                      fill="none"
                      viewBox="0 0 24 24"
                      stroke="currentColor"
                      strokeWidth="2"
                    >
                      <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1" />
                    </svg>

                    Sign Out
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
