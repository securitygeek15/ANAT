window.addEventListener("load", () => {
    if (typeof Chart === "undefined") return;

    Chart.defaults.color = "#7f8a9d";
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
                    backgroundColor: ["#5b8cff", "#4dd8d0"],
                    borderColor: "#0e131d",
                    borderWidth: 5,
                    hoverOffset: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "72%",
                plugins: {
                    legend: {
                        position: "right",
                        labels: { usePointStyle: true, pointStyle: "circle", padding: 22, boxWidth: 7 }
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
                    backgroundColor: ["#ff627d", "#ffb547", "#46d29a"],
                    borderRadius: 5,
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
                        grid: { color: "rgba(255, 255, 255, 0.055)" },
                        border: { display: false }
                    }
                },
                plugins: { legend: { display: false } }
            }
        });
    }
});
