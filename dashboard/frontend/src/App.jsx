import Dashboard from './Dashboard'
import { LightSpeed } from './components/ui/light-speed'
import './index.css'

function App() {
  return (
    <>
      {/* Full-page animated background — fixed so it never scrolls */}
      <LightSpeed
        className="fixed inset-0 w-full h-full bg-black overflow-hidden"
        speed={0.4}
      />
      {/* Dashboard content rendered above the shader */}
      <div style={{ position: 'relative', zIndex: 1 }}>
        <Dashboard />
      </div>
    </>
  )
}

export default App
