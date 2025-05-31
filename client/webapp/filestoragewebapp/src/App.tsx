import React, { useState, useEffect } from "react";
import GoogleDriveClone from "./app/google-drive-clone";
import AuthPage from "./components/AuthPage";

export default function App() {
  const [loggedInUser, setLoggedInUser] = useState<string | null>(null);

  // Check for keep-signed-in on mount
  useEffect(() => {
    const saved = localStorage.getItem("drive_username");
    if (saved) setLoggedInUser(saved);
  }, []);

  if (!loggedInUser) {
    return <AuthPage onAuthSuccess={setLoggedInUser} />;
  }

  return <GoogleDriveClone />;
}
