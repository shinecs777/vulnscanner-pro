document.addEventListener("DOMContentLoaded", function() {
    const splash = document.getElementById("splash-screen");
    const text1 = document.getElementById("splash-text-1");
    const btn = document.getElementById("splash-btn");
    const dashboard = document.getElementById("main-dashboard-content");

    // CHECK IF SPLASH WAS ALREADY SEEN
    if (sessionStorage.getItem("splash_seen") === "true") {
        // Skip splash, show dashboard immediately
        if (splash) splash.style.display = "none";
        if (dashboard) dashboard.style.display = "block";
        return; 
    }

    // PLAY SPLASH SEQUENCE
    setTimeout(() => {
        if (text1) {
            text1.classList.remove("hidden");
            text1.classList.add("animate-type");
            
            setTimeout(() => {
                text1.classList.add("animate-dust");
                
                setTimeout(() => {
                    if (btn) {
                        btn.classList.remove("hidden");
                        btn.classList.add("fade-in");
                    }
                }, 2500);
            }, 4500);
        }
    }, 500);

    // BUTTON CLICK
    if (btn) {
        btn.addEventListener("click", function() {
            sessionStorage.setItem("splash_seen", "true"); // Mark as seen
            splash.style.display = "none";
            dashboard.style.display = "block";
            window.scrollTo(0, 0);
        });
    }
});
