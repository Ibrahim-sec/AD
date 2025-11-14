import React, { useState, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import {
  getCustomScenarioById,
  saveCustomScenario,
  deleteCustomScenario,
} from "../utils/scenarioStorage";
import {
  validateScenarioStructure,
  validateStep,
} from "../utils/scenarioValidation";
import { templates, getTemplate, getEmptyScenario } from "../utils/scenarioTemplates";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./ui/card";
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { Textarea } from "./ui/textarea";
import { Label } from "./ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import { Separator } from "./ui/separator";
import { toast } from "sonner";
import {
  Plus,
  Trash2,
  Save,
  ChevronUp,
  ChevronDown,
  AlertTriangle,
} from "lucide-react";
import { ScrollArea } from "./ui/scroll-area";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "./ui/accordion";

// Helper component for a single step in the editor
const StepEditor = ({ step, index, updateStep, removeStep, moveStep }) => {
  const [validationErrors, setValidationErrors] = useState([]);

  // Validate step on mount and on update
  useEffect(() => {
    // The existing validateStep function takes the step object and its index
    const errors = validateStep(step, index);
    setValidationErrors(errors);
  }, [step, index]);

  const handleUpdate = (field, value) => {
    const updatedStep = { ...step, [field]: value };
    updateStep(index, updatedStep);
  };

  const hasErrors = validationErrors.length > 0;

  // Helper to check if a specific error message exists for styling
  const hasError = (messagePart) => validationErrors.some(e => e.includes(messagePart));

  return (
    <Card className="mb-4 border-l-4 border-yellow-500/50">
      <CardHeader className="flex flex-row items-center justify-between p-4 pb-2">
        <CardTitle className="text-lg">Step {index + 1}: {step.description || 'Untitled'}</CardTitle>
        <div className="flex space-x-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => moveStep(index, index - 1)}
            disabled={index === 0}
            title="Move Up"
          >
            <ChevronUp className="h-4 w-4" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => moveStep(index, index + 1)}
            disabled={index === 0} // Disabled logic will be handled by parent component
            title="Move Down"
          >
            <ChevronDown className="h-4 w-4" />
          </Button>
          <Button
            variant="destructive"
            size="icon"
            onClick={() => removeStep(index)}
            title="Remove Step"
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="p-4 pt-0">
        {hasErrors && (
          <div className="mb-4 rounded-md border border-red-500 bg-red-900/20 p-3 text-sm text-red-400">
            <div className="flex items-center">
              <AlertTriangle className="mr-2 h-4 w-4" />
              <span>Validation Errors:</span>
            </div>
            <ul className="mt-1 list-disc pl-5">
              {validationErrors.map((message, i) => (
                <li key={i}>{message}</li>
              ))}
            </ul>
          </div>
        )}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div className="space-y-2 col-span-full">
            <Label htmlFor={`description-${index}`}>Step Description</Label>
            <Input
              id={`description-${index}`}
              value={step.description || ""}
              onChange={(e) => handleUpdate("description", e.target.value)}
              placeholder="What does this step do?"
              className={hasError("missing required field: description") ? "border-red-500" : ""}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`expectedCommand-${index}`}>
              Expected Command (User Input)
            </Label>
            <Input
              id={`expectedCommand-${index}`}
              value={step.expectedCommand || ""}
              onChange={(e) => handleUpdate("expectedCommand", e.target.value)}
              placeholder="e.g., nmap -sV 10.0.1.10"
              className={hasError("missing required field: expectedCommand") ? "border-red-500" : ""}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor={`scoreValue-${index}`}>Score Value</Label>
            <Input
              id={`scoreValue-${index}`}
              type="number"
              value={step.scoreValue || 10}
              onChange={(e) =>
                handleUpdate("scoreValue", parseInt(e.target.value) || 0)
              }
              placeholder="Points for this step"
              className={hasError("scoreValue must be a number") ? "border-red-500" : ""}
            />
          </div>
        </div>

        <div className="mt-4 space-y-2">
          <Label htmlFor={`attackerOutput-${index}`}>Attacker Output (Terminal Response)</Label>
          <Textarea
            id={`attackerOutput-${index}`}
            value={step.attackerOutput || ""}
            onChange={(e) => handleUpdate("attackerOutput", e.target.value)}
            placeholder="What the attacker sees in their terminal..."
            className={hasError("missing required field: attackerOutput") ? "border-red-500" : ""}
          />
        </div>

        <div className="mt-4 space-y-2">
          <Label htmlFor={`internalOutput-${index}`}>Internal Server Output (Log Response)</Label>
          <Textarea
            id={`internalOutput-${index}`}
            value={step.internalOutput || ""}
            onChange={(e) => handleUpdate("internalOutput", e.target.value)}
            placeholder="What appears in the internal server logs (optional)..."
          />
        </div>

        <div className="mt-4 space-y-2">
          <Label htmlFor={`dcOutput-${index}`}>Domain Controller Output (Log Response)</Label>
          <Textarea
            id={`dcOutput-${index}`}
            value={step.dcOutput || ""}
            onChange={(e) => handleUpdate("dcOutput", e.target.value)}
            placeholder="What appears in DC logs (optional)..."
          />
        </div>

        <Accordion type="single" collapsible className="w-full mt-4">
          <AccordionItem value="hints">
            <AccordionTrigger className="text-sm">
              Optional: Hints
            </AccordionTrigger>
            <AccordionContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor={`hintShort-${index}`}>Short Hint</Label>
                <Input
                  id={`hintShort-${index}`}
                  value={step.hintShort || ""}
                  onChange={(e) => handleUpdate("hintShort", e.target.value)}
                  placeholder="A small nudge."
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor={`hintFull-${index}`}>Full Hint</Label>
                <Input
                  id={`hintFull-${index}`}
                  value={step.hintFull || ""}
                  onChange={(e) => handleUpdate("hintFull", e.target.value)}
                  placeholder="The full command or concept."
                />
              </div>
            </AccordionContent>
          </AccordionItem>
        </Accordion>
      </CardContent>
    </Card>
  );
};

const ScenarioEditor = () => {
  const [scenario, setScenario] = useState(getEmptyScenario());
  const [validationErrors, setValidationErrors] = useState(null);
  const [isSaving, setIsSaving] = useState(false);
  const [location, setLocation] = useLocation();

  // Load scenario from URL parameter on mount
  useEffect(() => {
    const params = new URLSearchParams(location.split("?")[1]);
    const id = params.get("id");
    if (id) {
      const loadedScenario = getCustomScenarioById(id);
      if (loadedScenario) {
        setScenario(loadedScenario);
        toast.success(`Scenario "${loadedScenario.name}" loaded.`);
      } else {
        toast.error("Scenario not found. Loading default template.");
        setScenario(getEmptyScenario());
      }
    }
  }, [location]);

  const updateMetadata = (field, value) => {
    setScenario((prev) => ({ ...prev, [field]: value }));
  };

  const updateMission = (field, value) => {
    setScenario((prev) => ({
      ...prev,
      mission: {
        ...prev.mission,
        [field]: value,
      },
    }));
  };

  const updateMachine = (machineType, field, value) => {
    setScenario((prev) => ({
      ...prev,
      machines: {
        ...prev.machines,
        [machineType]: {
          ...prev.machines[machineType],
          [field]: value,
        },
      },
    }));
  };

  const updateStep = useCallback((index, updatedStep) => {
    setScenario((prev) => {
      const newSteps = [...prev.steps];
      newSteps[index] = updatedStep;
      return { ...prev, steps: newSteps };
    });
  }, []);

  const addStep = () => {
    setScenario((prev) => ({
      ...prev,
      steps: [
        ...prev.steps,
        {
          id: prev.steps.length + 1,
          description: "New Step Description",
          expectedCommand: "",
          attackerOutput: "",
          internalOutput: "",
          dcOutput: "",
          hintShort: "",
          hintFull: "",
          scoreValue: 10,
        },
      ],
    }));
  };

  const removeStep = useCallback((index) => {
    setScenario((prev) => ({
      ...prev,
      steps: prev.steps.filter((_, i) => i !== index),
    }));
  }, []);

  const moveStep = useCallback((fromIndex, toIndex) => {
    if (toIndex < 0 || toIndex >= scenario.steps.length) return;
    setScenario((prev) => {
      const newSteps = [...prev.steps];
      const [movedStep] = newSteps.splice(fromIndex, 1);
      newSteps.splice(toIndex, 0, movedStep);
      return { ...prev, steps: newSteps };
    });
  }, [scenario.steps.length]);

  const handleSave = () => {
    setIsSaving(true);
    const { valid, errors } = validateScenarioStructure(scenario);

    if (!valid) {
      setValidationErrors(errors);
      toast.error("Validation failed. Please check the errors below.");
      setIsSaving(false);
      return;
    }

    setValidationErrors(null);
    const savedScenario = saveCustomScenario(scenario);

    if (savedScenario) {
      toast.success(`Scenario "${savedScenario.name}" saved successfully!`);
      // Update URL to reflect the new ID if it was a new scenario
      if (!scenario.id) {
        setLocation(`/editor?id=${savedScenario.id}`, { replace: true });
      }
      setScenario(savedScenario); // Update state with the new ID
    } else {
      toast.error("Failed to save scenario to local storage.");
    }
    setIsSaving(false);
  };

  const handleDelete = () => {
    if (
      window.confirm(
        `Are you sure you want to delete the scenario "${scenario.name}"?`
      )
    ) {
      if (scenario.id && deleteCustomScenario(scenario.id)) {
        toast.success(`Scenario "${scenario.name}" deleted.`);
        setScenario(getEmptyScenario());
        setLocation("/editor", { replace: true });
      } else {
        toast.error("Failed to delete scenario.");
      }
    }
  };

  const handleTemplateSelect = (templateId) => {
    const template = getTemplate(templateId);
    if (template) {
      // getTemplate already returns a deep copy with a new ID
      setScenario(template);
      toast.info(`Loaded template: ${template.name}`);
    }
  };

  // Export scenario as JSON
  const handleExport = () => {
    const { valid, errors } = validateScenarioStructure(scenario);
    if (!valid) {
      setValidationErrors(errors);
      toast.error("Validation failed. Cannot export invalid scenario.");
      return;
    }

    const dataStr = JSON.stringify(scenario, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${scenario.name.replace(/\s/g, '_')}_${scenario.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success("Scenario exported successfully!");
  };

  // Import scenario from JSON
  const handleImport = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        try {
          const data = JSON.parse(event.target.result);
          const { valid, errors } = validateScenarioStructure(data);
          
          if (!valid) {
            setValidationErrors(errors);
            toast.error("Import failed. Imported JSON is invalid.");
            return;
          }

          // Assign a new custom ID to the imported scenario
          data.id = `custom_${Date.now()}`;
          data.isCustom = true;
          
          setScenario(data);
          setValidationErrors(null);
          toast.success(`Scenario "${data.name}" imported successfully!`);
          setLocation("/editor/new", { replace: true }); // Clear URL param
        } catch (error) {
          setValidationErrors([`Invalid JSON file: ${error.message}`]);
          toast.error("Import failed. File is not valid JSON.");
        }
      };
      reader.readAsText(file);
    };
    input.click();
  };

  return (
    <ScrollArea className="h-full p-6">
      <div className="max-w-4xl mx-auto">
        <h1 className="text-3xl font-bold tracking-tight">Scenario Editor</h1>
        <p className="text-muted-foreground mt-1">
          Create, edit, and manage your own Active Directory attack scenarios.
        </p>

        <Separator className="my-6" />

        {/* Action Bar */}
        <div className="flex justify-between items-center mb-6">
          <div className="flex space-x-2">
            <Button onClick={handleSave} disabled={isSaving}>
              <Save className="mr-2 h-4 w-4" />
              {isSaving ? "Saving..." : "Save Scenario"}
            </Button>
            {scenario.id && (
              <Button variant="outline" onClick={handleDelete}>
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </Button>
            )}
          </div>
          <div className="flex space-x-2">
            <Select onValueChange={handleTemplateSelect}>
              <SelectTrigger className="w-[200px]">
                <SelectValue placeholder="Load Template" />
              </SelectTrigger>
              <SelectContent>
                {templates.map((template) => (
                  <SelectItem key={template.id} value={template.id}>
                    {template.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="outline" onClick={handleExport}>
              <Code className="mr-2 h-4 w-4" />
              Export JSON
            </Button>
            <Button variant="outline" onClick={handleImport}>
              <FileText className="mr-2 h-4 w-4" />
              Import JSON
            </Button>
          </div>
        </div>

        {/* Global Validation Errors */}
        {validationErrors && validationErrors.length > 0 && (
          <Card className="mb-6 border-red-500 bg-red-900/20 text-red-400">
            <CardHeader>
              <CardTitle className="flex items-center text-lg">
                <AlertTriangle className="mr-2 h-5 w-5" />
                Scenario Validation Failed
              </CardTitle>
              <CardDescription className="text-red-300">
                Please correct the following errors before saving:
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="list-disc pl-5">
                {validationErrors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}

        {/* Metadata Card */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Scenario Metadata</CardTitle>
            <CardDescription>
              Define the core details of your attack scenario.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="name">Scenario Name</Label>
              <Input
                id="name"
                value={scenario.name || ""}
                onChange={(e) => updateMetadata("name", e.target.value)}
                placeholder="e.g., Pass-the-Hash Attack"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="difficulty">Difficulty</Label>
              <Select
                value={scenario.difficulty || "Intermediate"}
                onValueChange={(value) => updateMetadata("difficulty", value)}
              >
                <SelectTrigger id="difficulty">
                  <SelectValue placeholder="Select difficulty" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="Beginner">Beginner</SelectItem>
                  <SelectItem value="Intermediate">Intermediate</SelectItem>
                  <SelectItem value="Advanced">Advanced</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2 col-span-full">
              <Label htmlFor="target">Mission Target</Label>
              <Input
                id="target"
                value={scenario.mission?.target || ""}
                onChange={(e) => updateMission("target", e.target.value)}
                placeholder="e.g., Domain Admin"
              />
            </div>
            <div className="space-y-2 col-span-full">
              <Label htmlFor="objective">Mission Objective</Label>
              <Textarea
                id="objective"
                value={scenario.mission?.objective || ""}
                onChange={(e) => updateMission("objective", e.target.value)}
                placeholder="A brief summary of the attack path and learning objectives."
              />
            </div>
          </CardContent>
        </Card>

        {/* Machine Configuration */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle>Machine Configuration</CardTitle>
            <CardDescription>
              Define the names and IP addresses for the simulated machines.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {['attacker', 'internal', 'dc'].map(machineType => (
              <div key={machineType} className="space-y-2 border p-3 rounded-md">
                <h4 className="font-semibold text-sm">{machineType.charAt(0).toUpperCase() + machineType.slice(1)} Machine</h4>
                <div className="space-y-2">
                  <Label htmlFor={`${machineType}-name`}>Name</Label>
                  <Input
                    id={`${machineType}-name`}
                    value={scenario.machines?.[machineType]?.name || ""}
                    onChange={(e) => updateMachine(machineType, 'name', e.target.value)}
                    placeholder="e.g., ATTACKER01"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor={`${machineType}-ip`}>IP Address</Label>
                  <Input
                    id={`${machineType}-ip`}
                    value={scenario.machines?.[machineType]?.ip || ""}
                    onChange={(e) => updateMachine(machineType, 'ip', e.target.value)}
                    placeholder="e.g., 10.0.0.5"
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Steps Editor */}
        <h2 className="text-2xl font-semibold tracking-tight mb-4">
          Scenario Steps ({scenario.steps?.length || 0})
        </h2>
        <div className="space-y-4">
          {scenario.steps?.map((step, index) => (
            <StepEditor
              key={index}
              step={step}
              index={index}
              updateStep={updateStep}
              removeStep={removeStep}
              moveStep={moveStep}
            />
          ))}
        </div>

        <Button onClick={addStep} className="mt-6 w-full" variant="secondary">
          <Plus className="mr-2 h-4 w-4" />
          Add New Step
        </Button>

        <Separator className="my-6" />

        <div className="flex justify-center">
          <Button onClick={handleSave} disabled={isSaving}>
            <Save className="mr-2 h-4 w-4" />
            {isSaving ? "Saving..." : "Save Scenario"}
          </Button>
        </div>
      </div>
    </ScrollArea>
  );
};

export default ScenarioEditor;
