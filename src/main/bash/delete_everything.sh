#!/bin/bash
kubectl delete namespace openunison
kubectl delete namespace openunison-deploy
kubectl delete certificatesigningrequest openunison.openunison.svc.cluster.local
kubectl delete certificatesigningrequest amq.openunison.svc.cluster.local
kubectl delete certificatesigningrequest kubernetes-dashboard.kube-system.svc.cluster.local