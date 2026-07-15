window.addEventListener("load", () => {
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    if (reduceMotion || typeof gsap === "undefined") return;

    gsap.set([
        ".sidebar",
        ".topbar",
        ".hero-panel",
        ".metric-card",
        ".filter-bar",
        ".panel",
        "tbody tr"
    ], {
        willChange: "transform, opacity"
    });

    const timeline = gsap.timeline({
        defaults: {
            ease: "power3.out"
        }
    });

    timeline
        .from(".sidebar", {
            x: -18,
            opacity: 0,
            duration: 0.5
        })
        .from(".topbar", {
            y: -14,
            opacity: 0,
            duration: 0.42
        }, "-=0.3")
        .from(".hero-panel", {
            y: 18,
            opacity: 0,
            duration: 0.5
        }, "-=0.2")
        .from(".metric-card", {
            y: 14,
            opacity: 0,
            duration: 0.42,
            stagger: 0.06
        }, "-=0.24")
        .from(".filter-bar", {
            y: 12,
            opacity: 0,
            duration: 0.36
        }, "-=0.22")
        .from(".panel", {
            y: 16,
            opacity: 0,
            duration: 0.46,
            stagger: 0.07
        }, "-=0.2")
        .from("tbody tr", {
            y: 8,
            opacity: 0,
            duration: 0.28,
            stagger: 0.025
        }, "-=0.22");

    gsap.set([
        ".sidebar",
        ".topbar",
        ".hero-panel",
        ".metric-card",
        ".filter-bar",
        ".panel",
        "tbody tr"
    ], {
        clearProps: "willChange",
        delay: 1.5
    });
});

// Theme Toggle Logic
document.addEventListener("DOMContentLoaded", () => {
    const toggleBtn = document.getElementById("theme-toggle");
    if (!toggleBtn) return;
    
    // Check local storage for preference
    const currentTheme = localStorage.getItem("theme");
    if (currentTheme === "dark") {
        document.documentElement.classList.add("dark-mode");
    }
    
    toggleBtn.addEventListener("click", () => {
        document.documentElement.classList.toggle("dark-mode");
        let theme = "light";
        if (document.documentElement.classList.contains("dark-mode")) {
            theme = "dark";
        }
        localStorage.setItem("theme", theme);
    });
});
