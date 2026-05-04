import { Eye, Users, Code } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger } from './ui/tabs';

interface LayeredViewToggleProps {
  currentView: 'executive' | 'analyst' | 'technical';
  onViewChange: (view: 'executive' | 'analyst' | 'technical') => void;
}

export function LayeredViewToggle({ currentView, onViewChange }: LayeredViewToggleProps) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-2">
      <Tabs value={currentView} onValueChange={(v) => onViewChange(v as any)}>
        <TabsList className="grid w-full grid-cols-3 bg-slate-800">
          <TabsTrigger 
            value="executive" 
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-white"
          >
            <Eye className="w-4 h-4 mr-2" />
            Executive
          </TabsTrigger>
          <TabsTrigger 
            value="analyst" 
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-white"
          >
            <Users className="w-4 h-4 mr-2" />
            Analyst
          </TabsTrigger>
          <TabsTrigger 
            value="technical" 
            className="data-[state=active]:bg-slate-700 data-[state=active]:text-white"
          >
            <Code className="w-4 h-4 mr-2" />
            Technical
          </TabsTrigger>
        </TabsList>
      </Tabs>
      <div className="mt-2 px-2 text-xs text-slate-300">
        {currentView === 'executive' && 'High-level summary and key findings'}
        {currentView === 'analyst' && 'Detailed analysis with context and recommendations'}
        {currentView === 'technical' && 'Complete technical data, headers, and IoCs'}
      </div>
    </div>
  );
}