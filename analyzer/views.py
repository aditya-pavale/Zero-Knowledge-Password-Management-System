from rest_framework import generics, serializers, status
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAdminRole
from audit.models import AuditLog
from audit.service import log_event

from .models import AnalysisReport
from .service import analyze


class AnalyzeRequestSerializer(serializers.Serializer):
    bandit = serializers.DictField(required=False)
    semgrep = serializers.DictField(required=False)
    zap = serializers.DictField(required=False)
    findings = serializers.ListField(child=serializers.DictField(), required=False, max_length=500)
    use_llm = serializers.BooleanField(required=False, default=True)

    def validate(self, attrs):
        if not any(attrs.get(k) for k in ("bandit", "semgrep", "zap", "findings")):
            raise serializers.ValidationError("Provide at least one of bandit, semgrep, zap or findings.")
        return attrs


class AnalysisReportSerializer(serializers.ModelSerializer):
    created_by = serializers.CharField(source="created_by.username", default="", read_only=True)

    class Meta:
        model = AnalysisReport
        fields = ["id", "created_by", "created_at", "sources", "engine", "findings_count", "summary", "results"]
        read_only_fields = fields


class AnalyzeView(APIView):
    permission_classes = [IsAdminRole]
    throttle_scope = "analyzer"

    def post(self, request):
        serializer = AnalyzeRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        engine, results, summary = analyze(data, use_llm=data["use_llm"])
        sources = [k for k in ("bandit", "semgrep", "zap", "findings") if data.get(k)]
        report = AnalysisReport.objects.create(
            created_by=request.user, sources=sources, engine=engine,
            findings_count=len(results), summary=summary, results=results,
        )
        log_event(request, AuditLog.Event.ANALYZER_RUN, target=report,
                  metadata={"engine": engine, "findings": len(results)})
        return Response(AnalysisReportSerializer(report).data, status=status.HTTP_201_CREATED)


class ReportListView(generics.ListAPIView):
    permission_classes = [IsAdminRole]
    serializer_class = AnalysisReportSerializer
    queryset = AnalysisReport.objects.select_related("created_by")
