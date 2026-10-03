'use client';

import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { api } from '@/lib/api';
import { useApi } from '@/lib/use-api';
import { LoadingState, ErrorState } from '@/components/data-state';
import { Bug, ShieldAlert, Send } from 'lucide-react';

export default function XssDemoPage() {
  const commentsQ = useApi(() => api.comments(), []);
  const productsQ = useApi(() => api.products(), []);
  const [productId, setProductId] = useState('');
  const [content, setContent] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const submit = async (safe: boolean) => {
    const pid = productId || productsQ.data?.[0]?.id || '';
    if (!pid || !content.trim()) {
      setFormError('Select a product and enter comment content.');
      return;
    }
    setSubmitting(true);
    setFormError(null);
    try {
      await api.postComment(pid, content, safe);
      setContent('');
      commentsQ.reload();
    } catch (e) {
      setFormError(e instanceof Error ? e.message : 'Failed to post comment');
    } finally {
      setSubmitting(false);
    }
  };

  if (commentsQ.loading || productsQ.loading) return <LoadingState label="Loading comments..." />;
  const err = commentsQ.error ?? productsQ.error;
  if (err || !commentsQ.data || !productsQ.data) {
    return <ErrorState message={err ?? 'No data'} onRetry={() => { commentsQ.reload(); productsQ.reload(); }} />;
  }
  const comments = commentsQ.data;
  const products = productsQ.data;

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center gap-3 mb-1">
        <div className="w-10 h-10 rounded-lg bg-destructive/10 border border-destructive/20 flex items-center justify-center">
          <Bug className="w-5 h-5 text-destructive" />
        </div>
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Stored XSS Demo (VULN-005)</h1>
          <p className="text-muted-foreground text-sm">Compare the vulnerable and sanitized comment endpoints</p>
        </div>
      </div>

      <Card className="border-destructive/40 bg-destructive/5">
        <CardContent className="p-4 flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-destructive shrink-0 mt-0.5" />
          <p className="text-sm text-muted-foreground">
            <span className="font-medium text-destructive">Intentional vulnerability.</span> Comments posted to the vulnerable
            endpoint (POST /api/comments) are stored as raw HTML and rendered below with dangerouslySetInnerHTML.
            Any script or event handler you submit will run in this page. Comments from POST /api/comments/safe are
            sanitized and rendered as plain text. Use only in this lab.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Post a comment</CardTitle>
          <CardDescription>Try: {'<img src=x onerror="alert(document.domain)">'}</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <Select value={productId || products[0]?.id || ''} onValueChange={setProductId}>
            <SelectTrigger className="w-full md:w-[320px]"><SelectValue placeholder="Product" /></SelectTrigger>
            <SelectContent>
              {products.map(p => <SelectItem key={p.id} value={p.id}>{p.name}</SelectItem>)}
            </SelectContent>
          </Select>
          <Textarea value={content} onChange={e => setContent(e.target.value)} placeholder="Comment content (HTML allowed on the vulnerable endpoint)" rows={3} />
          {formError && <ErrorState message={formError} />}
          <div className="flex flex-wrap gap-2">
            <Button variant="destructive" size="sm" disabled={submitting} onClick={() => void submit(false)}>
              <Send className="w-3.5 h-3.5 mr-1.5" /> Post (vulnerable)
            </Button>
            <Button variant="outline" size="sm" disabled={submitting} onClick={() => void submit(true)}>
              <Send className="w-3.5 h-3.5 mr-1.5" /> Post (safe)
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Comments ({comments.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {comments.length === 0 && <p className="text-sm text-muted-foreground">No comments yet.</p>}
          {comments.map(c => (
            <div key={c.id} className="p-3 rounded-lg bg-muted/30 border border-border">
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-medium">{c.userName}</span>
                <span className="text-[10px] font-mono text-muted-foreground">{c.productId}</span>
                <Badge variant="outline" className={`text-[9px] ${c.sanitized ? 'border-success/40 text-success' : 'border-destructive/40 text-destructive'}`}>
                  {c.sanitized ? 'sanitized' : 'raw HTML'}
                </Badge>
                <span className="text-[10px] text-muted-foreground ml-auto">{c.createdAt.slice(0, 19).replace('T', ' ')}</span>
              </div>
              {c.sanitized ? (
                <div className="text-sm whitespace-pre-wrap break-words">{c.content}</div>
              ) : (
                // VULN-005 (intentional): unsanitized stored HTML rendered as-is to demonstrate stored XSS.
                <div className="text-sm break-words" dangerouslySetInnerHTML={{ __html: c.content }} />
              )}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
