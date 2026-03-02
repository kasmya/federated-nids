/**
 * NIDS Dashboard - Matrix Rain Animation
 * Creates the iconic falling code effect
 */

class MatrixRain {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        
        this.ctx = this.canvas.getContext('2d');
        this.drops = [];
        this.characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()_+{}|:<>?';
        this.fontSize = 14;
        this.columns = 0;
        this.isRunning = true;
        
        this.init();
        this.animate();
    }
    
    init() {
        this.resize();
        window.addEventListener('resize', () => this.resize());
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.columns = Math.floor(this.canvas.width / this.fontSize);
        this.drops = [];
        
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.random() * -100;
        }
    }
    
    draw() {
        // Semi-transparent black background for trail effect
        this.ctx.fillStyle = 'rgba(10, 10, 15, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Green text
        this.ctx.fillStyle = '#00ff33';
        this.ctx.font = `${this.fontSize}px monospace`;
        
        for (let i = 0; i < this.drops.length; i++) {
            const char = this.characters[Math.floor(Math.random() * this.characters.length)];
            const x = i * this.fontSize;
            const y = this.drops[i] * this.fontSize;
            
            // Varying green shades
            const green = Math.floor(Math.random() * 156) + 100;
            this.ctx.fillStyle = `rgb(0, ${green}, 51)`;
            
            this.ctx.fillText(char, x, y);
            
            // Reset drop to top randomly
            if (y > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            
            this.drops[i]++;
        }
    }
    
    animate() {
        if (!this.isRunning) return;
        
        this.draw();
        requestAnimationFrame(() => this.animate());
    }
    
    stop() {
        this.isRunning = false;
    }
    
    start() {
        this.isRunning = true;
        this.animate();
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.matrixRain = new MatrixRain('matrix');
});

