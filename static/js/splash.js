document.addEventListener("DOMContentLoaded", function() {
    const splash = document.getElementById("splash-screen");
    const text1 = document.getElementById("splash-text-1");
    const btn = document.getElementById("splash-btn");
    const dashboard = document.getElementById("main-dashboard-content");

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

    if (btn) {
        btn.addEventListener("click", function() {
            splash.style.display = "none";
            dashboard.style.display = "block";
            window.scrollTo(0, 0);
        });
    }
});