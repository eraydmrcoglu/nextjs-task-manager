"use client";
import React, { useEffect } from "react";
import LoginForm from "../Components/auth/LoginForm/LoginForm";
import { useUserContext } from "@/context/userContext";
import { useRouter } from "next/navigation";

function page() {
  const { user } = useUserContext();
  const router = useRouter();

  useEffect(() => {
    if (user && user._id) {
      router.push("/");
    }
  }, [user, router]);

  if (user && user._id) {
    return null;
  }

  return (
    <div className="auth-page w-full h-full flex justify-center items-center">
      <LoginForm />
    </div>
  );
}

export default page;
