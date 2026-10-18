-- update_v2.sql — شغّله في Supabase > SQL Editor (بعد schema.sql)
-- يضيف: اسم مستخدم فريد، رفض الدفعات، وتخزين صور اللوجو.

-- 1) اسم المستخدم لازم يكون فريد (بدون حساسية لحالة الأحرف) وبصيغة صحيحة
--    لو ظهر خطأ هنا يبقى فيه اسمين مكررين في جدول profiles، غيّر واحد منهم وأعد التشغيل.
create unique index if not exists profiles_username_lower_key on profiles (lower(username));

create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare un text := coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1));
begin
  if un !~ '^[A-Za-z0-9_]{3,20}$' then raise exception 'bad_username'; end if;
  insert into profiles(id, username) values (new.id, un);   -- التكرار يوقف التسجيل
  insert into wallets(user_id) values (new.id);
  return new;
end $$;

-- 2) رفض دفعة (أدمن فقط) مع تسجيلها في سجل العمليات
create or replace function reject_payment(p_id bigint) returns void
language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  update payments set status='rejected', reviewed_by=auth.uid() where id=p_id and status='pending';
  if not found then raise exception 'not_pending'; end if;
  insert into audit_logs(actor,action,details) values (auth.uid(),'payment_rejected',jsonb_build_object('payment',p_id));
end $$;
revoke all on function reject_payment from public, anon;
grant execute on function reject_payment to authenticated;

-- 3) تخزين صور اللوجو: القراءة للجميع، والرفع/الحذف للأدمن فقط
insert into storage.buckets (id, name, public) values ('branding','branding',true) on conflict (id) do nothing;
drop policy if exists "branding public read" on storage.objects;
drop policy if exists "branding admin insert" on storage.objects;
drop policy if exists "branding admin update" on storage.objects;
drop policy if exists "branding admin delete" on storage.objects;
create policy "branding public read" on storage.objects for select using (bucket_id = 'branding');
create policy "branding admin insert" on storage.objects for insert with check (bucket_id = 'branding' and is_admin());
create policy "branding admin update" on storage.objects for update using (bucket_id = 'branding' and is_admin());
create policy "branding admin delete" on storage.objects for delete using (bucket_id = 'branding' and is_admin());
