// Copyright 2026 LightweightAuth Contributors
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	v1alpha1 "github.com/mikeappsec/lightweightauth/api/crd/v1alpha1"
)

const (
	instanceFinalizer = "lightweightauth.io/instance-cleanup"
	defaultImage      = "ghcr.io/mikeappsec/lightweightauth:latest"
)

// InstanceReconciler reconciles LwauthInstance CRDs into running
// lwauth Deployments + Services + PDB.
type InstanceReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme

	// DefaultImage is used when spec.image and spec.version are empty.
	DefaultImage string
}

// SetupWithManager registers the reconciler with a controller-runtime manager.
func (r *InstanceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.LwauthInstance{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Complete(r)
}

// Reconcile ensures the desired lwauth Deployment/Service/PDB match the
// LwauthInstance spec.
func (r *InstanceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx).WithValues("lwauthinstance", req.NamespacedName)

	var instance v1alpha1.LwauthInstance
	if err := r.Client.Get(ctx, req.NamespacedName, &instance); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion.
	if !instance.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&instance, instanceFinalizer) {
			// Clean up owned resources (handled by owner references, but
			// we remove the finalizer to let the CR be deleted).
			controllerutil.RemoveFinalizer(&instance, instanceFinalizer)
			if err := r.Client.Update(ctx, &instance); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&instance, instanceFinalizer) {
		controllerutil.AddFinalizer(&instance, instanceFinalizer)
		if err := r.Client.Update(ctx, &instance); err != nil {
			return ctrl.Result{}, err
		}
	}

	targetNS := instance.Spec.TargetNamespace
	if targetNS == "" {
		targetNS = instance.Namespace
	}

	// Reconcile Deployment.
	deploy, err := r.reconcileDeployment(ctx, &instance, targetNS)
	if err != nil {
		logger.Error(err, "failed to reconcile Deployment")
		r.setCondition(&instance, v1alpha1.InstanceConditionReady, metav1.ConditionFalse, v1alpha1.InstanceReasonCreateFailed, err.Error())
		_ = r.Client.Status().Update(ctx, &instance)
		return ctrl.Result{}, err
	}

	// Reconcile Service.
	if err := r.reconcileService(ctx, &instance, targetNS); err != nil {
		logger.Error(err, "failed to reconcile Service")
		return ctrl.Result{}, err
	}

	// Reconcile PDB.
	if err := r.reconcilePDB(ctx, &instance, targetNS); err != nil {
		logger.Error(err, "failed to reconcile PDB")
		return ctrl.Result{}, err
	}

	// Update status.
	now := metav1.Now()
	instance.Status.LastReconcile = &now
	instance.Status.ObservedGeneration = instance.Generation

	readyReplicas := deploy.Status.ReadyReplicas
	desiredReplicas := int32(2)
	if instance.Spec.Replicas != nil {
		desiredReplicas = *instance.Spec.Replicas
	}
	instance.Status.Replicas = fmt.Sprintf("%d/%d", readyReplicas, desiredReplicas)
	instance.Status.Ready = readyReplicas >= desiredReplicas

	if instance.Status.Ready {
		r.setCondition(&instance, v1alpha1.InstanceConditionReady, metav1.ConditionTrue, v1alpha1.InstanceReasonReconciled, "All replicas ready")
	} else {
		r.setCondition(&instance, v1alpha1.InstanceConditionReady, metav1.ConditionFalse, v1alpha1.InstanceReasonProgressing, "Waiting for replicas")
	}

	if err := r.Client.Status().Update(ctx, &instance); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue to check readiness if not yet ready.
	if !instance.Status.Ready {
		return ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	return ctrl.Result{}, nil
}

func (r *InstanceReconciler) reconcileDeployment(ctx context.Context, instance *v1alpha1.LwauthInstance, ns string) (*appsv1.Deployment, error) {
	replicas := int32(2)
	if instance.Spec.Replicas != nil {
		replicas = *instance.Spec.Replicas
	}

	image := r.resolveImage(instance)

	labels := map[string]string{
		"app.kubernetes.io/name":       "lwauth",
		"app.kubernetes.io/instance":   instance.Name,
		"app.kubernetes.io/managed-by": "lwauth-controlplane",
	}

	deploy := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: ns,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, deploy, func() error {
		deploy.Labels = labels
		deploy.Spec.Replicas = &replicas
		deploy.Spec.Selector = &metav1.LabelSelector{
			MatchLabels: labels,
		}
		deploy.Spec.Template.ObjectMeta.Labels = labels
		deploy.Spec.Template.Spec.Containers = []corev1.Container{
			{
				Name:  "lwauth",
				Image: image,
				Ports: []corev1.ContainerPort{
					{Name: "http", ContainerPort: 8080, Protocol: corev1.ProtocolTCP},
					{Name: "grpc", ContainerPort: 9001, Protocol: corev1.ProtocolTCP},
					{Name: "admin", ContainerPort: 8081, Protocol: corev1.ProtocolTCP},
				},
				Resources: r.resolveResources(instance),
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: "/healthz",
							Port: intstr.FromString("admin"),
						},
					},
					InitialDelaySeconds: 5,
					PeriodSeconds:       10,
				},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path: "/readyz",
							Port: intstr.FromString("admin"),
						},
					},
					InitialDelaySeconds: 3,
					PeriodSeconds:       5,
				},
			},
		}
		// Zone-spread topology constraint.
		deploy.Spec.Template.Spec.TopologySpreadConstraints = []corev1.TopologySpreadConstraint{
			{
				MaxSkew:           1,
				TopologyKey:       "topology.kubernetes.io/zone",
				WhenUnsatisfiable: corev1.ScheduleAnyway,
				LabelSelector:     &metav1.LabelSelector{MatchLabels: labels},
			},
		}
		return controllerutil.SetControllerReference(instance, deploy, r.Scheme)
	})
	if err != nil {
		return nil, fmt.Errorf("reconcile deployment (%s): %w", op, err)
	}
	return deploy, nil
}

func (r *InstanceReconciler) reconcileService(ctx context.Context, instance *v1alpha1.LwauthInstance, ns string) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "lwauth",
		"app.kubernetes.io/instance":   instance.Name,
		"app.kubernetes.io/managed-by": "lwauth-controlplane",
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: ns,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, svc, func() error {
		svc.Labels = labels
		svc.Spec.Selector = labels
		svc.Spec.Ports = []corev1.ServicePort{
			{Name: "http", Port: 8080, TargetPort: intstr.FromString("http"), Protocol: corev1.ProtocolTCP},
			{Name: "grpc", Port: 9001, TargetPort: intstr.FromString("grpc"), Protocol: corev1.ProtocolTCP},
			{Name: "admin", Port: 8081, TargetPort: intstr.FromString("admin"), Protocol: corev1.ProtocolTCP},
		}
		return controllerutil.SetControllerReference(instance, svc, r.Scheme)
	})
	return err
}

func (r *InstanceReconciler) reconcilePDB(ctx context.Context, instance *v1alpha1.LwauthInstance, ns string) error {
	labels := map[string]string{
		"app.kubernetes.io/name":       "lwauth",
		"app.kubernetes.io/instance":   instance.Name,
		"app.kubernetes.io/managed-by": "lwauth-controlplane",
	}

	minAvailable := intstr.FromInt32(1)
	if instance.Spec.PodDisruptionBudget != nil && instance.Spec.PodDisruptionBudget.MinAvailable != nil {
		minAvailable = intstr.FromInt32(*instance.Spec.PodDisruptionBudget.MinAvailable)
	}

	pdb := &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instance.Name,
			Namespace: ns,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, pdb, func() error {
		pdb.Labels = labels
		pdb.Spec.MinAvailable = &minAvailable
		pdb.Spec.Selector = &metav1.LabelSelector{MatchLabels: labels}
		return controllerutil.SetControllerReference(instance, pdb, r.Scheme)
	})
	return err
}

func (r *InstanceReconciler) resolveImage(instance *v1alpha1.LwauthInstance) string {
	if instance.Spec.Image != "" {
		return instance.Spec.Image
	}
	if instance.Spec.Version != "" {
		return "ghcr.io/mikeappsec/lightweightauth:" + instance.Spec.Version
	}
	if r.DefaultImage != "" {
		return r.DefaultImage
	}
	return defaultImage
}

func (r *InstanceReconciler) resolveResources(instance *v1alpha1.LwauthInstance) corev1.ResourceRequirements {
	if instance.Spec.Resources.Requests != nil || instance.Spec.Resources.Limits != nil {
		return instance.Spec.Resources
	}
	return corev1.ResourceRequirements{
		Requests: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("100m"),
			corev1.ResourceMemory: resource.MustParse("128Mi"),
		},
		Limits: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("1"),
			corev1.ResourceMemory: resource.MustParse("512Mi"),
		},
	}
}

func (r *InstanceReconciler) setCondition(instance *v1alpha1.LwauthInstance, condType string, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&instance.Status.Conditions, metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: instance.Generation,
		LastTransitionTime: metav1.Now(),
	})
}
