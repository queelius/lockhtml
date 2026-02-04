# When Simpler Is Better: Model Selection for Series System Reliability

*How much complexity does your reliability model actually need? We ran
millions of simulations to find out --- and the answer may surprise you.*

---

## The Problem Every Reliability Engineer Faces

Imagine you're responsible for a system made of five components arranged in
series --- if any one fails, the whole system goes down. A jet engine, a
manufacturing line, or a communications relay chain all follow this pattern.

You've collected failure data, but there's a catch: you often don't know
*which* component caused the failure. Maybe diagnosing the root cause is too
expensive. Maybe the failure destroyed the evidence. All you know is *when*
the system failed and, at best, a short list of suspects. This is called
**masked failure data**, and it's the norm in industrial reliability testing.

Now you need to estimate each component's reliability. You assume each
component's lifetime follows a [Weibull
distribution](https://en.wikipedia.org/wiki/Weibull_distribution) --- the
workhorse of reliability engineering --- parameterized by a *shape* (how the
failure rate changes over time) and a *scale* (how long the component
typically lasts). For a five-component system, that's 10 parameters to
estimate from imperfect data.

Here's the question: **do you really need all 10?**

## The "Goldilocks" Simplification

There's a natural hierarchy of models you could use, ranging from the fully
general (every component gets its own shape and scale) down to the trivially
simple (all components are identical). We investigated where the sweet spot
lies.

| Model | Parameters | System is Weibull? |
|-------|-----------|-------------------|
| Full (heterogeneous) | 2*m* = 10 | No |
| **Common shape** | ***m* + 1 = 6** | **Yes** |
| Common scale | *m* + 1 = 6 | No |
| Fully homogeneous | 2 | Yes |

The **common-shape model** stands out. It assumes all components age in the
same way (same shape parameter) but can have different characteristic
lifetimes (different scale parameters). This is physically natural for
well-designed systems: components are manufactured to similar standards and
operate under similar conditions, so they share similar aging behavior, but
they differ in size, material, and load capacity, giving them different
lifetimes.

And here's the mathematical payoff: the common-shape model is the *only*
single-parameter simplification that makes the system lifetime itself
Weibull. This isn't just elegance --- it means you get closed-form formulas
for system MTTF, reliability curves, and hazard functions. Everything
downstream becomes simpler.

We proved this as a formal theorem: if each component has lifetime
*T_j* ~ Weibull(*k*, *lambda_j*), then the system lifetime
*T* = min(*T_1*, ..., *T_m*) is Weibull(*k*, *lambda_s*) where *lambda_s*
combines the individual scales. No other constraint on the full model gives
you this.

But is the simplification *justified*? When does it break down?

## 30,000 Observations Aren't Enough to Tell the Difference

We ran Monte Carlo simulations using a baseline 5-component system designed
to represent a realistic, well-engineered product. The components have shape
parameters between 1.13 and 1.26 (all indicating mild wear-out) --- a
coefficient of variation (CV) of about 4%.

We applied a likelihood ratio test (LRT) at each sample size to ask: *is
there statistically significant evidence that the components have different
shapes?*

**The answer: no, not even with 30,000 observations.**

For a well-designed system with shape CV below 10%, the LRT cannot reject
the simpler model regardless of sample size. In practical terms, you could
collect data from 30,000 system failures and *still* not have evidence that
you need the more complex model.

This is a feature, not a limitation. It means the simpler model genuinely
fits. And by using it, you:

- **Halve the parameter count** (6 vs. 10 for a 5-component system)
- **Reduce estimator variance** (fewer parameters to estimate = tighter confidence intervals)
- **Gain analytical tractability** (system-level Weibull formulas)

## But Heterogeneity Is Quickly Detectable

The robustness cuts both ways. When components *do* have meaningfully
different shapes, the LRT picks it up fast.

We varied a single component's shape parameter to create increasing levels
of heterogeneity and tracked how quickly the LRT rejects the common-shape
model:

| Shape CV | *n* = 500 | *n* = 1,000 | *n* = 5,000 |
|----------|----------|------------|------------|
| 0% | 6% | 5% | 5% |
| ~5.5% | 9% | 13% | 53% |
| ~8% | 12% | 26% | 91% |
| ~11% | 24% | 46% | 100% |

At 8% CV, the test achieves 91% power with 5,000 observations. At 11% CV,
even 1,000 observations give you a coin-flip chance of detecting it, and
5,000 is essentially certain.

## The Practical Decision Framework

Our results translate into a simple decision tree:

1. **Shape CV < 10%**: Use the reduced model confidently. You won't reject
   it even with massive samples, and you gain all the benefits of
   simplicity.

2. **Shape CV 10--20%**: It depends on your sample size. With fewer than
   500 observations, the reduced model is unlikely to be rejected and its
   lower variance may be preferable. With larger samples, consider the full
   model.

3. **Shape CV > 25%**: Use the full model. Even modest samples will reject
   the reduced model.

Of course, you need *some* initial estimate of shape CV to use this
framework. A preliminary fit of the full model on your data gives you the
shape estimates you need.

## LRT vs. AIC vs. BIC: Which Model Selection Tool?

The LRT isn't the only option. We compared it against AIC (Akaike
Information Criterion) and BIC (Bayesian Information Criterion) using the
same simulation data.

Under the null hypothesis (components truly have the same shape):

| Criterion | False positive rate | Verdict |
|-----------|-------------------|---------|
| LRT (alpha = 0.05) | 4.6--6.8% | Well-calibrated |
| AIC | 8.2--12.4% | Liberal (~2x nominal) |
| BIC | 0--0.2% | Over-conservative |

**AIC** is too eager to select the complex model. Its fixed penalty
doesn't grow with sample size, so as you collect more data, random
fluctuations in the log-likelihood increasingly exceed the penalty
threshold. It *does* detect heterogeneity earliest, so it can be useful for
exploratory analysis where false positives are cheap.

**BIC** goes the other way. Its penalty grows as log(*n*), making it
increasingly reluctant to select the full model. At *n* = 1,000 with 10%
shape CV, BIC selects the full model only 3.2% of the time while the LRT
achieves 69% power. BIC's conservatism aligns with its well-known
preference for parsimony, but it makes it nearly blind to the subtle
heterogeneity that characterizes well-designed systems.

**The LRT** hits the sweet spot: calibrated false positive rate, good
power, and a principled connection to hypothesis testing.

## What About Imperfect Data?

Real-world reliability data is messy. We tested the LRT under varying
levels of:

- **Masking** (probability that the true failure cause is hidden among
  decoys): from 5% to 70%
- **Censoring** (fraction of systems observed to fail before the study
  ends): from 50% to 100%

The key finding: **masking and censoring reduce power but do not inflate
Type I error.** The test remains well-calibrated even under harsh data
conditions. You might need more data to detect heterogeneity, but you won't
get fooled into seeing it when it isn't there.

## The Bottom Line

For well-designed series systems --- the kind that competent engineering
teams actually build --- the common-shape Weibull model is not just
adequate, it's *preferred*. It cuts the parameter space in half, makes the
system Weibull (unlocking a library of closed-form results), and cannot be
distinguished from the full model even with extraordinary amounts of data.

When shape heterogeneity *does* matter, the likelihood ratio test will
tell you, with well-calibrated error rates and predictable power curves
that let you plan your testing accordingly.

The full paper, simulation code, and data are available on [the project
repository](https://github.com/queelius/reliability-estimation-in-series-systems-model-selection).

---

*This post summarizes results from "Model Selection for Reliability
Estimation in Series Systems" by Alex Towell.*
