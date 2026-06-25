window.addEventListener("load", () => {
    if (typeof Chart === "undefined") return;

    Chart.defaults.color = "#657386";
    Chart.defaults.font.family = "DM Sans";
    Chart.defaults.font.size = 11;

    const protocolCanvas = document.getElementById("protocolChart");

    if (protocolCanvas && typeof tcpCount !== "undefined") {
        new Chart(protocolCanvas, {
            type: "doughnut",
            data: {
                labels: ["TCP", "UDP"],
                datasets: [{
                    data: [tcpCount, udpCount],
                    backgroundColor: ["#3f6ed8", "#0f9f82"],
                    borderColor: "#ffffff",
                    borderWidth: 4,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "72%",
                plugins: {
                    legend: {
                        position: "right",
                        labels: { usePointStyle: true, pointStyle: "rectRounded", padding: 18, boxWidth: 8 }
                    }
                }
            }
        });
    }

    const severityCanvas = document.getElementById("severityChart");

    if (severityCanvas && typeof severityData !== "undefined") {
        new Chart(severityCanvas, {
            type: "bar",
            data: {
                labels: ["High", "Medium", "Low"],
                datasets: [{
                    data: severityData,
                    backgroundColor: ["#d84760", "#bd7418", "#168a55"],
                    borderRadius: 4,
                    borderSkipped: false,
                    barThickness: 28
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { display: false }, border: { display: false } },
                    y: {
                        beginAtZero: true,
                        ticks: { precision: 0 },
                        grid: { color: "rgba(101, 115, 134, 0.16)" },
                        border: { display: false }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
});
