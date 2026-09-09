#!/usr/bin/env python3
"""Render the two deployment locations and enforce executable HA chart contracts."""
import subprocess
import unittest
import yaml

class UnifiedChart(unittest.TestCase):
    def render(self, *args):
        p = subprocess.run(['helm','template','test','deploy/helm/sre',*args],text=True,capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr)
        return [d for d in yaml.safe_load_all(p.stdout) if d]
    def test_orchestrator_ha(self):
        docs=self.render()
        dep=next(d for d in docs if d['kind']=='Deployment')
        self.assertEqual(dep['spec']['replicas'],2)
        self.assertEqual(dep['spec']['strategy']['type'],'RollingUpdate')
        pod=dep['spec']['template']['spec']
        self.assertFalse(pod['automountServiceAccountToken'])
        self.assertTrue(pod['topologySpreadConstraints'])
        self.assertTrue(any(d['kind']=='PodDisruptionBudget' for d in docs))
        self.assertFalse(any(d['kind'] in ('Role','ClusterRole') for d in docs))
    def test_agent_only_and_execution_opt_in(self):
        args=['--set','orchestrator.enabled=false','--set','agent.enabled=true','--set','agent.orchestratorURL=https://sre.example.com','--set','agent.organizationID=o','--set','agent.clusterID=c','--set','agent.applicationID=a','--set','agent.expectedClusterUID=uid','--set','agent.namespaces={work}']
        docs=self.render(*args)
        deps=[d for d in docs if d['kind']=='Deployment']
        self.assertEqual(len(deps),1)
        pod=deps[0]['spec']['template']['spec']
        self.assertEqual(len(pod['containers']),1)
        self.assertIn('--in-cluster',pod['containers'][0]['args'])
        self.assertNotIn('--execution-enabled',pod['containers'][0]['args'])
        rules=[r for d in docs if d['kind'] in ('Role','ClusterRole') for r in d['rules']]
        self.assertFalse(any('delete' in r['verbs'] for r in rules))
        enabled=self.render(*args,'--set','agent.executionEnabled=true')
        rules=[r for d in enabled if d['kind']=='Role' for r in d['rules']]
        self.assertTrue(any('delete' in r['verbs'] and r['resources']==['pods'] for r in rules))

if __name__=='__main__': unittest.main()
