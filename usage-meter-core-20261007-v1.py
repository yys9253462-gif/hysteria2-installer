"""真实计数器累计核心；调用方须在门户 data_lock 内调用并原子持久化整个 state。
读取计数器不得 clear/reset。epoch 应取服务 InvocationID，而非 PID。
历史 used_bytes 不用作真实计量初值；首次接入默认只建立基线。
"""
import copy

ACCOUNTING_REVISION = "2026-10-12-real-usage-v2"


def apply_sample(state, source, epoch, counters, sampled_at):
    if source not in ('hysteria', 'reality'):
        raise ValueError('unknown source')
    if not isinstance(epoch, str) or not epoch:
        raise ValueError('missing service epoch')
    if not isinstance(counters, dict):
        raise ValueError('counters must be a dict')
    clean = {}
    for uid, pair in counters.items():
        if not isinstance(uid, str) or not isinstance(pair, dict):
            raise ValueError('invalid counter entry')
        tx, rx = pair.get('tx'), pair.get('rx')
        if type(tx) is not int or type(rx) is not int or min(tx, rx) < 0:
            raise ValueError('invalid byte counters')
        clean[uid] = {'tx': tx, 'rx': rx}
    # 先完整验证，失败时不能留下部分写入。
    new = copy.deepcopy(state)
    sources = new.setdefault('sources', {})
    previous = sources.get(source)
    # 旧备份 / 截断写入可能留下缺 epoch 或 counters 的残缺状态，直接取键会
    # KeyError，而 runtime 每个 poll 周期都会重试 → 计量永久失效，只能手工
    # 删掉 usage_meter 才能恢复（2026-10-29 修）。
    # 结构不合法时把它当作首次采样，并显式记一条缺口。
    if previous is not None:
        if (not isinstance(previous, dict)
                or not isinstance(previous.get('epoch'), str)
                or not previous.get('epoch')
                or not isinstance(previous.get('counters'), dict)):
            previous = None
            sources.pop(source, None)
            new.setdefault('gaps', []).append(
                {'source': source, 'at': sampled_at,
                 'reason': 'corrupt_state_reset'})
    totals = new.setdefault('totals', {})
    # 加上增量前校验原值，负数/布尔值不能被一次采样洗成正常整数。
    for uid in clean:
        total_bytes(new, uid)
    reset_users = []
    corrupt_users = []
    first_sample = previous is None
    new_epoch = previous is not None and previous['epoch'] != epoch
    cursors = {} if previous is None else dict(previous['counters'])
    if new_epoch:
        cursors = {}
    deltas = {}
    # 游标为防止重复累计而保留；速率只能使用相邻两轮都出现的计数。
    sampled_users = set()
    if previous is not None:
        if 'sampled_users' not in previous:
            sampled_users = set(cursors)  # 兼容没有相邻采样元数据的旧状态。
        else:
            recorded = previous['sampled_users']
            if isinstance(recorded, list) and all(isinstance(uid, str) for uid in recorded):
                sampled_users = set(recorded)
    for uid, pair in clean.items():
        old = cursors.get(uid)
        if first_sample:
            delta = 0  # 不声称此前进程内的历史计数属于新计量窗口。
        elif new_epoch or uid not in cursors:
            delta = pair['tx'] + pair['rx']
        elif (not isinstance(old, dict) or
              any(type(old.get(k)) is not int or old[k] < 0 for k in ('tx', 'rx'))):
            delta = 0
            corrupt_users.append(uid)
        elif pair['tx'] < old['tx'] or pair['rx'] < old['rx']:
            # 同一 epoch 出现倒退：不能断言是完整 reset（也可能有人 clear）。
            # 保守重建基线并显式标记缺口，不重复累加旧值。
            delta = 0
            reset_users.append(uid)
        else:
            delta = pair['tx'] - old['tx'] + pair['rx'] - old['rx']
        bucket = totals.setdefault(uid, {})
        bucket[source] = bucket.get(source, 0) + delta
        cursors[uid] = pair
        # 分方向记录本轮增量（2026-10-08）：/traffic-speed 需要 tx/rx 分开算速率，
        # 而上面的 delta 是二者之和（用于 totals 累计）。
        # ⚠️ 仅在真能拆出方向时才采样，且只在有字节流动时采样：
        #   - 方向不可知（新 epoch 或该用户首次出现）时不采样。那种情况下
        #     delta 是「自服务启动起的累计」而非本轮增量，当成 5 秒的增量
        #     会算出荒谬的速率尖峰。
        #   - 零字节增量也通知速率端点，及时清除上一轮非零速度。
        if (old is not None and not new_epoch and not first_sample
                and uid in sampled_users
                and uid not in reset_users and uid not in corrupt_users):
            deltas[uid] = (pair['tx'] - old['tx'], pair['rx'] - old['rx'])
    # 消失的用户保持旧游标：临时空响应不能让再次出现的累计值重复计数。
    sources[source] = {'epoch': epoch, 'counters': cursors, 'sampled_at': sampled_at,
                       'sampled_users': list(clean)}
    if first_sample:
        sources[source]['baseline_at'] = sampled_at
    elif 'baseline_at' in previous:
        sources[source]['baseline_at'] = previous['baseline_at']
    gaps = new.setdefault('gaps', [])
    if new_epoch:
        gaps.append({'source': source, 'at': sampled_at,
                     'reason': 'service_restart_unsampled_tail_unknown'})
    if reset_users:
        gaps.append({'source': source, 'at': sampled_at,
                     'reason': 'counter_regressed_rebased', 'users': reset_users})
    if corrupt_users:
        gaps.append({'source': source, 'at': sampled_at,
                     'reason': 'corrupt_cursor_rebased', 'users': corrupt_users})
    new['gaps'] = gaps[-100:]
    state.clear()
    state.update(new)
    # deltas 的 value 是 (tx, rx) 元组 —— 见循环内的注释。
    return {'deltas': deltas, 'baseline_only': first_sample, 'epoch_changed': new_epoch,
            'counter_regressions': reset_users}


def total_bytes(state, uid):
    totals = state.get('totals', {})
    if not isinstance(totals, dict):
        raise ValueError('invalid totals')
    bucket = totals.get(uid, {})
    if (not isinstance(bucket, dict)
            or any(type(value) is not int or value < 0 for value in bucket.values())):
        raise ValueError('invalid user totals')
    return sum(bucket.values())
