using System.Text.Json;

namespace Observe;

public sealed class ObserverErrorLog
{
    public DateTimeOffset At {get;set;}=DateTimeOffset.UtcNow;
    public string Model {get;set;}="";
    public string Stage {get;set;}="";
    public int? HttpStatus {get;set;}
    public string Code {get;set;}="";
    public string Type {get;set;}="";
    public string Parameter {get;set;}="";
    public string ProviderMessage {get;set;}="";
    public string RequestId {get;set;}="";
    public string ResponseId {get;set;}="";
    public string IncompleteReason {get;set;}="";
    public int InputTokenUpperBound {get;set;}
    public int InputBudget {get;set;}
    public int OutputBudget {get;set;}
    public int ContextWindow {get;set;}
    public int IncludedEvents {get;set;}
    public int OmittedEvents {get;set;}
    public int OmittedMessages {get;set;}
    public string[] UnverifiedCitations {get;set;}=[];
    public string Note {get;set;}="Diagnostic fields only. API keys, authorization headers, chat text and raw evidence are not included. Input sizing is a conservative UTF-8 token upper bound, not billed token usage.";
    public static string Clean(string value,string key="")
    {
        if(key.Length>0)value=value.Replace(key,"[redacted key]",StringComparison.Ordinal);
        value=Evidence.Redact(value);return value[..Math.Min(6000,value.Length)];
    }
    public void ReadProvider(JsonElement data,string key)
    {
        string Str(JsonElement e,string property)=>e.TryGetProperty(property,out var p)&&p.ValueKind==JsonValueKind.String?p.GetString()??"":"";
        var response=data.TryGetProperty("response",out var r)&&r.ValueKind==JsonValueKind.Object?r:data;
        var responseId=Clean(Str(response,"id"),key);if(responseId.Length>0)ResponseId=responseId;
        if(response.TryGetProperty("incomplete_details",out var details)&&details.ValueKind==JsonValueKind.Object)IncompleteReason=Clean(Str(details,"reason"),key);
        var error=response.TryGetProperty("error",out var err)&&err.ValueKind==JsonValueKind.Object?err:data;
        Code=Clean(Str(error,"code"),key);Type=Clean(Str(error,"type"),key);Parameter=Clean(Str(error,"param"),key);ProviderMessage=Clean(Str(error,"message"),key);
    }
    public string Explanation()
    {
        if(Code=="unverified_citations")return "Observe could not verify one or more event references in this answer. The generated text is retained above, but claims using those references are unverified. Inspect the evidence or retry. See the error log for the unmatched references.";
        if(Code is "insufficient_quota" or "billing_hard_limit_reached")return "OpenAI reports insufficient API credit or a billing limit. Check the API project's billing and spending limits.";
        if(Code is "context_length_exceeded" or "max_context_length_exceeded")return "OpenAI rejected the request size. Choose a shorter evidence period or start a new chat.";
        if(HttpStatus==401||Code=="invalid_api_key")return "OpenAI rejected the API key. Update it in plugin settings.";
        if(HttpStatus is 403 or 404||Code=="model_not_found")return "Your OpenAI project cannot access this model. Choose another model in the dropdown.";
        if(HttpStatus==429||Code=="rate_limit_exceeded")return "OpenAI reports a rate limit. Wait before retrying or check your project's usage limits.";
        if(IncompleteReason=="max_output_tokens")return "The model used its response token budget before finishing. Ask a narrower question. The log shows the input and output budgets.";
        if(IncompleteReason=="content_filter")return "OpenAI stopped this response because of a content filter. See the error log for the provider's reason.";
        if(Code=="cancelled")return "Response stopped. Any text received is retained above. Your message and evidence are saved.";
        if(Code=="timeout")return "The OpenAI request timed out. Any text received is retained above. Your message and evidence are saved; try again.";
        if(ProviderMessage.Length>0)return "OpenAI could not complete this answer: "+ProviderMessage[..Math.Min(350,ProviderMessage.Length)]+" Your evidence is saved.";
        return "OpenAI could not complete this answer. Your evidence is saved. Open the error log for diagnostic details.";
    }
}
public sealed class ObserverProviderException(ObserverErrorLog log):Exception(log.Explanation())
{
    public ObserverErrorLog Log {get;}=log;
}
