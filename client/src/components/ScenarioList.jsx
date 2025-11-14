import React from 'react';
import { deleteCustomScenario } from '../utils/scenarioStorage';
import { Link } from 'wouter';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Trash2, Edit } from 'lucide-react';
import { toast } from 'sonner';

export default function ScenarioList({ 
  scenarios, 
  title, 
  onScenarioUpdate, // Callback to refresh the list in App.jsx
}) {
  const handleDelete = (id, name) => {
    if (window.confirm(`Are you sure you want to delete the custom scenario "${name}"?`)) {
      if (deleteCustomScenario(id)) {
        toast.success(`Scenario "${name}" deleted.`);
        onScenarioUpdate();
      } else {
        toast.error(`Failed to delete scenario "${name}".`);
      }
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-2xl font-semibold tracking-tight">{title}</h2>
        <Link href="/editor/new">
          <Button>+ Create New Scenario</Button>
        </Link>
      </div>

      {scenarios.length === 0 ? (
        <Card className="p-6 text-center">
          <CardTitle className="text-xl">No Custom Scenarios Found</CardTitle>
          <CardDescription className="mt-2">
            Click "Create New Scenario" to build your first custom attack path.
          </CardDescription>
        </Card>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map(scenario => (
            <Card key={scenario.id} className="flex flex-col justify-between">
              <CardHeader className="pb-2">
                <CardTitle className="text-lg">{scenario.name}</CardTitle>
                <CardDescription className={`difficulty-badge difficulty-${scenario.difficulty.toLowerCase()}`}>
                  {scenario.difficulty}
                </CardDescription>
              </CardHeader>
              <CardContent className="pt-2">
                <p className="text-sm text-muted-foreground mb-2">Target: {scenario.mission?.target || 'N/A'}</p>
                <p className="text-sm text-muted-foreground">Steps: {scenario.steps?.length || 0}</p>
              </CardContent>
              <div className="p-4 pt-0 flex justify-end space-x-2">
                <Link href={`/editor/${scenario.id}`}>
                  <Button variant="outline" size="icon" title="Edit Scenario">
                    <Edit className="h-4 w-4" />
                  </Button>
                </Link>
                <Button 
                  variant="destructive" 
                  size="icon" 
                  title="Delete Scenario"
                  onClick={() => handleDelete(scenario.id, scenario.name)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
