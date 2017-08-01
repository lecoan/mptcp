/*
 *	MPTCP implementation - Linked Increase congestion control Algorithm (LIA)   MPTCP子流策略：耦合拥塞控制算法
 * 
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer & Author:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <net/tcp.h>
#include <net/mptcp.h>

#include <linux/module.h>

/* Scaling is done in the numerator with alpha_scale_num and in the denominator
 * with alpha_scale_den.
 *
 * To downscale, we just need to use alpha_scale.
 *
 * We have: alpha_scale = alpha_scale_num / (alpha_scale_den ^ 2)
 */
static int alpha_scale_den = 10;   //分母
static int alpha_scale_num = 32;   //分子
static int alpha_scale = 12;    //用于模拟整数alpha

struct mptcp_ccc {         //mptcp_coupled_congestion_control
	u64	alpha;
	bool	forced_update;
};

static inline int mptcp_ccc_sk_can_send(const struct sock *sk)    //sock *sk为原始socket
{
	return mptcp_sk_can_send(sk) && tcp_sk(sk)->srtt_us;     //以μs为单位的srtt
}                                          //tcp_sk为把sock结构转换为tcp_sock结构的函数

static inline u64 mptcp_get_alpha(const struct sock *meta_sk)    //meta_sk：某一个源sock变量
{
	return ((struct mptcp_ccc *)inet_csk_ca(meta_sk))->alpha;  //inet_csk_ca调用inet_csk返回sock类型变量所指向的icsk_ca_priv变量
}

static inline void mptcp_set_alpha(const struct sock *meta_sk, u64 alpha)
{
	((struct mptcp_ccc *)inet_csk_ca(meta_sk))->alpha = alpha;
}

static inline u64 mptcp_ccc_scale(u32 val, int scale)
{
	return (u64) val << scale;       //移位并变为64bit变量
}

static inline bool mptcp_get_forced(const struct sock *meta_sk)
{
	return ((struct mptcp_ccc *)inet_csk_ca(meta_sk))->forced_update;
}

static inline void mptcp_set_forced(const struct sock *meta_sk, bool force)
{
	((struct mptcp_ccc *)inet_csk_ca(meta_sk))->forced_update = force;
}

static void mptcp_ccc_recalc_alpha(const struct sock *sk)      //求α
{
	const struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	const struct sock *sub_sk;
	int best_cwnd = 0, best_rtt = 0, can_send = 0;
	u64 max_numerator = 0, sum_denominator = 0, alpha = 1;

	if (!mpcb)
		return;

	/* Only one subflow left - fall back to normal reno-behavior
	 * (set alpha to 1)
	 */
	if (mpcb->cnt_established <= 1)
		goto exit;

	/* Do regular alpha-calculation for multiple subflows */

	/* Find the max numerator of the alpha-calculation */    //遍历子流求最大分子
	mptcp_for_each_sk(mpcb, sub_sk) {              //宏定义，替换了for
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);      //本函数定义的sock类型变量sub_sk被转换为tcp_sock类型的sub_tp变量
		u64 tmp;
  
		if (!mptcp_ccc_sk_can_send(sub_sk))              //若当前子流不能发送则跳过当前子流
			continue;

		can_send++;

		/* We need to look for the path, that provides the max-value.
		 * Integer-overflow is not possible here, because
		 * tmp will be in u64.
		 */
		tmp = div64_u64(mptcp_ccc_scale(sub_tp->snd_cwnd,          //64位除64位
				alpha_scale_num), (u64)sub_tp->srtt_us * sub_tp->srtt_us);
                                                         //static inline u64 div64_u64(u64 dividend, u64 divisor)
		if (tmp >= max_numerator) {              //获取最大分子,更新发送方cwnd和其rtt
			max_numerator = tmp;
			best_cwnd = sub_tp->snd_cwnd;
			best_rtt = sub_tp->srtt_us;
		}
	}

	/* No subflow is able to send - we don't care anymore */
	if (unlikely(!can_send))
		goto exit;

	/* Calculate the denominator */
	mptcp_for_each_sk(mpcb, sub_sk) {                //遍历所有子流，求分母
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);

		if (!mptcp_ccc_sk_can_send(sub_sk))
			continue;

		sum_denominator += div_u64(
				mptcp_ccc_scale(sub_tp->snd_cwnd,
						alpha_scale_den) * best_rtt,
						sub_tp->srtt_us);
	}
	sum_denominator *= sum_denominator;                //根据公式求分母平方
	if (unlikely(!sum_denominator)) {                       
		pr_err("%s: sum_denominator == 0, cnt_established:%d\n",             //若未求得，抛出错误
		       __func__, mpcb->cnt_established);
		mptcp_for_each_sk(mpcb, sub_sk) {
			struct tcp_sock *sub_tp = tcp_sk(sub_sk);
			pr_err("%s: pi:%d, state:%d\n, rtt:%u, cwnd: %u",
			       __func__, sub_tp->mptcp->path_index,
			       sub_sk->sk_state, sub_tp->srtt_us,
			       sub_tp->snd_cwnd);
		}
	}

	alpha = div64_u64(mptcp_ccc_scale(best_cwnd, alpha_scale_num), sum_denominator);

	if (unlikely(!alpha))             //仅一个子流，还原为传统tcp，令α=1
		alpha = 1; 

exit:
	mptcp_set_alpha(mptcp_meta_sk(sk), alpha);
}

static void mptcp_ccc_init(struct sock *sk)             //初始设置与传统tcp相同
{
	if (mptcp(tcp_sk(sk))) {
		mptcp_set_forced(mptcp_meta_sk(sk), 0);
		mptcp_set_alpha(mptcp_meta_sk(sk), 1);
	}
	/* If we do not mptcp, behave like reno: return */
}

static void mptcp_ccc_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{
	if (event == CA_EVENT_LOSS)
		mptcp_ccc_recalc_alpha(sk);
}
/*enum tcp_ca_event {
	CA_EVENT_TX_START,	 //first transmit when no packets in flight 
	CA_EVENT_CWND_RESTART,	 //congestion window restart 
	CA_EVENT_COMPLETE_CWR,	 //end of congestion recovery 
	CA_EVENT_LOSS,		 //loss timeout 
	CA_EVENT_ECN_NO_CE,	 //ECT set, but not CE marked 
	CA_EVENT_ECN_IS_CE,	 //received CE marked IP packet 
	CA_EVENT_DELAYED_ACK,	 //Delayed ack is sent 
	CA_EVENT_NON_DELAYED_ACK,
};*/

 /*MPTCP会在接收每一个ACK的时候，计算算法中的a。调用情况如下：
     tcp_ack()
               =>tcp_ca_event()
                    =>cwnd_event()
                         =>mptcp_ccc_cwnd_event()*/
static void mptcp_ccc_set_state(struct sock *sk, u8 ca_state)
{
	if (!mptcp(tcp_sk(sk)))         //当前不是mptcp状态
		return;

	mptcp_set_forced(mptcp_meta_sk(sk), 1);
}

static void mptcp_ccc_cong_avoid(struct sock *sk, u32 ack, u32 acked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	const struct mptcp_cb *mpcb = tp->mpcb;
	int snd_cwnd;
 
	if (!mptcp(tp)) {                 //若退化为传统TCP
		tcp_reno_cong_avoid(sk, ack, acked);
		return;
	}

	if (!tcp_is_cwnd_limited(sk))             // 判断是否满足tp->snd_cwnd < 2 * tp->max_packets_out条件，若不满足则不退避
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh) {
		/* In "safe" area, increase. */
		tcp_slow_start(tp, acked);
		mptcp_ccc_recalc_alpha(sk);
		return;
	}

	if (mptcp_get_forced(mptcp_meta_sk(sk))) {      //当前已设定为mptcp？
		mptcp_ccc_recalc_alpha(sk);
		mptcp_set_forced(mptcp_meta_sk(sk), 0);       //？？？？？？？？？？？
	}

	if (mpcb->cnt_established > 1) {          //若当前建立的总子流数>1
		u64 alpha = mptcp_get_alpha(mptcp_meta_sk(sk));

		/* This may happen, if at the initialization, the mpcb
		 * was not yet attached to the sock, and thus
		 * initializing alpha failed.
		 */
		if (unlikely(!alpha))
			alpha = 1;

		snd_cwnd = (int) div_u64 ((u64) mptcp_ccc_scale(1, alpha_scale),   //static inline u64 div_u64(u64 dividend, u32 divisor)
						alpha);   //64位除32位

		/* snd_cwnd_cnt >= max (scale * tot_cwnd / alpha, cwnd)
		 * Thus, we select here the max value.
		 */
		if (snd_cwnd < tp->snd_cwnd)          //选取较大值
			snd_cwnd = tp->snd_cwnd;
	} else {                                //仅一个子流
		snd_cwnd = tp->snd_cwnd;
	}
        //以下和tcp几乎一样
	// 每接收到一个ACK，窗口增大(1/snd_cwnd)，使用cnt计数 
	if (tp->snd_cwnd_cnt >= snd_cwnd) {               // 线性增长计数器 >= 阈值 
		if (tp->snd_cwnd < tp->snd_cwnd_clamp) {      //发送窗口尚未达到阈值
			tp->snd_cwnd++;               //线性增加
			mptcp_ccc_recalc_alpha(sk);
		}

		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}

static struct tcp_congestion_ops mptcp_ccc = {   //结构成员定义更改
	.init		= mptcp_ccc_init,   /* initialize private data (optional) */
	.ssthresh	= tcp_reno_ssthresh,  /* return slow start threshold (required) */
	.cong_avoid	= mptcp_ccc_cong_avoid,  /* do new cwnd calculation (required) */
	.cwnd_event	= mptcp_ccc_cwnd_event,  /* call when cwnd event occurs (optional) */
	.set_state	= mptcp_ccc_set_state,  /* call before changing ca_state (optional) */
	.owner		= THIS_MODULE,
	.name		= "lia",
};

static int __init mptcp_ccc_register(void)
{
	BUILD_BUG_ON(sizeof(struct mptcp_ccc) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&mptcp_ccc);
}

static void __exit mptcp_ccc_unregister(void)
{
	tcp_unregister_congestion_control(&mptcp_ccc);
}

module_init(mptcp_ccc_register);
module_exit(mptcp_ccc_unregister);

MODULE_AUTHOR("Christoph Paasch, Sébastien Barré");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("MPTCP LINKED INCREASE CONGESTION CONTROL ALGORITHM");
MODULE_VERSION("0.1");
