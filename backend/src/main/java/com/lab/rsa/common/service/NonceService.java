package com.lab.rsa.common.service;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 防重放：时间窗 + nonce 一次性消耗（v5）。
 *
 * <h3>攻击场景</h3>
 * 攻击者截获一整包合法请求（密文解不开也改不了），原样再发给服务端。
 * 若没有「请求唯一性」校验，业务会被执行第二次——这就是重放攻击。
 *
 * <h3>两道闸</h3>
 * <ol>
 *   <li>{@code timestamp}：请求必须落在服务端时钟的允许窗口内，防止囤积旧包无限期重放</li>
 *   <li>{@code nonce}：随机串全局只许成功使用一次；同一包再来直接拒绝</li>
 * </ol>
 *
 * <p>本实现用进程内 {@link ConcurrentHashMap} 存已用 nonce，开箱即跑、适合课堂。
 * 多实例生产环境应换成 Redis（带 TTL），否则各节点无法共享去重状态。
 */
@Service
public class NonceService {
    /** 允许的客户端/服务端时钟偏差（±5 分钟） */
    private static final long REPLAY_WINDOW_MS = 5 * 60 * 1000L;
    /** 已用 nonce 在内存中保留多久，应 ≥ 时间窗，避免窗口内还能换节点重放 */
    private static final long NONCE_TTL_MS = 10 * 60 * 1000L;

    /** key=nonce，value=该记录过期的绝对时间 */
    private final ConcurrentHashMap<String, Long> usedNonceExpireAt = new ConcurrentHashMap<>();

    public long getReplayWindowMs() {
        return REPLAY_WINDOW_MS;
    }

    /**
     * 判断时间戳是否在允许窗口内。
     * 用绝对值比较，同时覆盖「客户端时钟偏快/偏慢」两种情况。
     */
    public boolean isTimestampWithinWindow(Long timestamp, long nowMs) {
        if (timestamp == null) {
            return false;
        }
        // abs：客户端时钟偏快或偏慢都算进同一窗口
        return Math.abs(nowMs - timestamp) <= REPLAY_WINDOW_MS;
    }

    /**
     * 原子地「消费」nonce：第一次返回 true 并记入；第二次起返回 false。
     *
     * <p>{@link ConcurrentHashMap#putIfAbsent} 保证并发下同一个 nonce 只会成功一次。
     *
     * @return true 表示本次放行；false 表示空 nonce 或已被用过
     */
    public boolean consumeNonce(String nonce, long nowMs) {
        if (!StringUtils.hasLength(nonce)) {
            return false;
        }
        // 先扫掉过期项，再插入，避免 Map 只增不减
        cleanup(nowMs);
        Long expireAt = nowMs + NONCE_TTL_MS;
        // putIfAbsent：已存在 → 返回旧值（非 null）→ 整体结果 false = 重放
        return usedNonceExpireAt.putIfAbsent(nonce, expireAt) == null;
    }

    /** 惰性清理过期 nonce，避免 Map 无限膨胀（教学用；生产靠 Redis TTL 更干净） */
    private void cleanup(long nowMs) {
        Iterator<Map.Entry<String, Long>> iterator = usedNonceExpireAt.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, Long> entry = iterator.next();
            // value 存的是「这条 nonce 记录何时作废」
            if (entry.getValue() <= nowMs) {
                iterator.remove();
            }
        }
    }
}
