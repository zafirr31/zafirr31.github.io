---
layout: post
author: zafirr
title:  "It's time we treated AI as cheating"
description: (I'm talking about CTFs)
date: 2026-07-17
last_modified_at: 2026-07-17
categories: blog 
lang: en
tags:
    - ai
    - opinion
    - ctf
---

<br>

I think it's clear just from the title, but I think it's time the CTF community treat the usage of AI during CTFs as cheating. In this post I'll try to go through the common opinions on this and try to give my own rebuttals to them.

## 1. It's 'just' a tool
This was and probably one of the first opinions regarding AI usage when AI was starting to get good (like late 2024 early 2025 I think?). Those who agree with this opinion often mention other tools like angr, which often can - without using AI - [solve challenges automatically](https://cothan.blog/posts/anti-debug-angr/)

Here's an example of someone with this opinion. I didn't include their name cause maybe their opinion has changed now, I didn't ask

![Error](/assets/images/its_time_we_treated_AI_as_cheating/1.png)

I don't agree that its 'just' another tool. Nowadays, AI can do A LOT more, basically as much as another human being. The way I see it, when we use an AI to solve a CTF challenge, what we are doing is 'hiring' another player (or more than 1) for a fee. We can choose how hard this player works and what tools it can use, and we can even _guide_ it at times to try and find the right solution. 

But in any in-person, limited player per team CTF, we would consider this **blatant** cheating, either by having more members than allowed or using remote help. Why don't we consider this about AI too? From my perspective its quite similar, especially with how good some of the models and harnessess have gotten.

The way we use it also differs from a tool. Look at the blog post I linked before on angr solving a challenge automatically. The author _understands_ what the problem they are trying to solve is. They understand that they can use angr. They understand what it's positives and negatives are, what its limitations are, etc. They didn't write `angr.solve(chall)` and somehow get it solved.

This is how we usually treat tools, we know when using a tool is appropriate and when its not. We also know the limitations (the 'ceiling') of the tool. This applies for decompilers, fuzzers, pwntools, etc. The limitations are clear, so we rely a lot on our own knowledge and skills as a CTF player to overcome problems that these tools cannot solve.

But AI isn't like a tool. The 'ceiling' is not clear (yet). We _can_ just say "solve this reversing challenge. Make no mistakes" and it'll poop the flag out. We don't need to understand the problem we are solving, we can just throw AI (and money) at it and it'll solve it for us. 

### Personal anecdote to end this part

Me and 2 of my juniors made a [quickjs](https://github.com/bellard/quickjs) exploitation challenge for an international CTF last year. We were very proud of it, and expected no one would be able to solve it only using AI. It turns out, someone did solve it with just GPT 5.3, and their prompt was "can you help me solve my ctf pwn challenge please, you can debug with anything you have full access on my terminal, can you complete it solve please". No special harness or anything, just codex. This was my turning point in thinking AI was just another tool.

## 2. Just make your challenge anti-AI
I think this opinion has died down a lot more since, but I still wanted to mention it. 

As a CTF challenge author, I've tried to make challenges 'anti-AI'. Many many many other CTF authors have tried the same. But in the end, our effort has become pointless. If we figure out some new way to prevent AI solves, either the AI providers make the model smarter using our challenge or someone just improves their own harness. Like I said in the previous point, the 'ceiling' for AIs is unknown at the moment. While I _personally_ don't believe AGI is possible, I think it's ability to solve problems in CTF-like scenarios will only increase for the time being.

It's different from designing a chall that angr can't solve. In the case of angr, it can only solve challenges where a clear goal is present, like a crackme or flag checker challenge. It also only works for certain challenges, namely compiled binaries. If you gave it a challenge to reverse a game written in javascript for example, it wouldn't be able to help as much.

In the last interation of [Sekai CTF](https://ctftime.org/event/3113), sahuang asked us to create challenges as anti-AI as possible. Lots of my peers worked very hard, creating challenges with zero days and/or chaining a bunch of N days and unique techniques. In the end, many challenges _still_ got slopped, which is just... depressing to me. Sekai CTF has ended for the time being, as sahuang believes creating jeopardy challenges that will get slopped by AI is not worth the time and effort. He has hopes for a different format in the future, which actually brings me to my next point.

## 3. We need a new format
Just a few days ago, Otter Sec released a blog post titled [Annoucing the Save CTFs Fund](https://osec.io/blog/save-ctfs-fund/). In it, they express that they are still optimistic for the CTF scene, despite AI basically killing the jeopardy format. They don't believe the fix is to ban AI, but instead a new format for CTFs is required. I applaude their optimism, even if I disagree with some of their points.

The jeopardy format is an incredibly good format. The objective is clear (for well-made challenges), the challenges are self-contained, the challenges are 'easy' to create, 'easy' to solve, and 'easy' to host ('easy' as in compared to other types of challenges and formats). This has allowed it to be used from beginner to expert level CTFs, while still staying competitive. I don't think I would have been interested in CTFs the way I am now if it weren't for this format.

A lot of the times when people say the jeopardy format is dead because of AI, I mention then lets remove the AI part, lets ban AI. They then say "but its impossible to ban AI, no way we can prevent everyone from using it", which is true (check out this post from [Hoshino Lina](https://infosec.exchange/@lina@vt.social/116198977436769476) which I think expresses this well). 

But, CTFs have always been a game of trust. Even before CTFs, we trusted teams wouldn't share flags, wouldn't share exploits, discuss between teams, have remote helpers during CTF finals, wouldn't attack the infrastructure. We trusted the CTF authors wouldn't share real malware (without mentioning it beforehand), wouldn't create unsolveable challenges, wouldn't steal exploits if we used 0 days. The entire community has been built on trust, do we really want to give up that trust because of AI?

I understand its impossible to completely prevent people from using AI. But given enough backlash and awareness in the community, we can still _try_ remove AI from the equation, without losing the great format that we have already. I don't want to end this part by seeming to say "just ban AI and trust each other". Obviously, we need to do _something_ if we want to solve this issue. I'm just not certain a new format is the most likely way we will achieve that.

## 4. AI is used in the real world
I work as security researcher. I use AI when I work (in a limiting way), and I wouldn't be in this position if it weren't for CTFs. But that doesn't mean AI has to be used in CTFs. I poke around the ICC (International Cybersecurity Championship) discord from time to time, and one of opinions by the organizers of that competition is that "completely banning AI isn't good because we want players to use it effectively, as its used in the real world" (I'm paraphrasing, but I think you understand what I mean). Because of this, they instead try to limit the usage of AI, particularly by limiting the amount of tokens used during the competition. They've also been exploring ideas of limiting the model, as models are only getting stronger these days.

This one I can see being an ok solution to the AI issue, at least for onsite CTFs. I believe there is a middleground to using AI, one where you can truly use it as a 'tool', without having the slop of auto solving challenges. During Cyber Jawara 2025 Finals, I pushed a rule to limit how players would use AI, trying to achieve that middleground of usefulness without the slop. It didn't work out perfectly, and we had to disqualify some teams after the competition ended, but I think we had a good effort at trying.

But I also have to mention that CTFs aren't meant to perfectly mimic the real world. We've known that for many years already. The bugs and tricks used in CTFs are very unlikely to be seen in the real world, but that doesn't matter. We play CTFs because they are a fun way of learning about systems. Learning their quirks, differences, bugs, limitations, all that stuff. There has basically never been a real world bug where a single byte write into glibc allows us to overwrite the stdin file struct and trigger FSOP on stdout, and yet I know exactly how to do that (bonus points if you know what challenge I'm referencing).

We play CTFs because we're hackers, and we love tinkering and sharing our knowledge with other hackers. While I owe my career to CTFs, I've always played because of the love of the game and not for career points. 

This is why I think it is perfectly fine if we try to limit the use of AI in CTFs. Even if during our real world jobs we are forced to use these slop machines, that doesn't mean our hobby as hackers has to use it too. I see AI as killing my favorite hobby, and if it's between mimicking the real world usage and saving my hobby, then I'm fine getting rid of AI.

## So let's agree that AI is cheating
Even if I haven't convinced you about anything, I hope at least you understand my position as a CTF player and author. I haven't played a CTF in a couple months, and that is mostly because it's really unfun playing a CTF in the slop era. When playing a CTF with my teammates, even they won't understand how they solved a challenge, as all they did was prompt an AI to slop it for them. Discussion post-CTF was always one of the best parts in playing a CTF, where each team shared their ideas in solving a challenge, _whether or not they solved it_. This is mostly gone in the slop era, where basically every team just says "eh, my AI solved it", "my idea was from so and so model", etc.

Before I started playing CTFs, the concept of [script kiddies](https://en.wikipedia.org/wiki/Script_kiddie) was shamed in the hacker world. I think now in the slop era we need a new terminology, so I've started calling people that only slop solve CTF challenges and slop exploit zero days as...

#### SLOP KIDDIES

Don't be a slop kiddie :)



