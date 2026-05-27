import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Analytics from './pages/Analytics'
import Events from './pages/Events'
import Exceptions from './pages/Exceptions'
import Deploy from './pages/Deploy'

function NavItem({ to, label }: { to: string; label: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `px-4 py-2 text-sm transition-colors rounded ${
          isActive
            ? 'text-amber-400 bg-zinc-800'
            : 'text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800/50'
        }`
      }
    >
      {label}
    </NavLink>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col">
        {/* Top nav */}
        <header className="border-b border-zinc-800 bg-zinc-950/80 sticky top-0 z-50 backdrop-blur">
          <div className="max-w-screen-xl mx-auto px-6 flex items-center h-14 gap-2">
            <span className="text-amber-500 font-bold tracking-tight mr-6">
              ⚡ WAF Agent
            </span>
            <NavItem to="/" label="Analytics" />
            <NavItem to="/events" label="Events" />
            <NavItem to="/exceptions" label="Exceptions" />
            <NavItem to="/deploy" label="Deploy" />
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 max-w-screen-xl mx-auto w-full px-6 py-6">
          <Routes>
            <Route path="/" element={<Analytics />} />
            <Route path="/events" element={<Events />} />
            <Route path="/exceptions" element={<Exceptions />} />
            <Route path="/deploy" element={<Deploy />} />
          </Routes>
        </main>

        <footer className="border-t border-zinc-900 py-3 text-center text-xs text-zinc-600">
          WAF Exception Agent · PoC
        </footer>
      </div>
    </BrowserRouter>
  )
}
