import Dashboard from './Dashboard'
import { LightSpeed } from './components/ui/light-speed'
import './index.css'

function App() {
  return (
    <div className="app-root">
      {/* Animation sits only behind nav + hero — not the whole page */}
      <div className="hero-canvas-wrapper">
        <LightSpeed
          className="absolute inset-0 w-full h-full bg-black overflow-hidden"
          speed={0.4}
        />
        {/* Fade the animation into the page background at the bottom */}
        <div className="hero-canvas-fade" />
      </div>

      {/* All dashboard content renders on top at z-index 1 */}
      <div className="app-content">
        <Dashboard />
      </div>
    </div>
  )
}

export default App
